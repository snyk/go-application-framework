// Package machineenrollment enrolls a device as a machine principal using a device token or a fleet key.
// The server answers with an OAuth client_id bound to a newly generated RSA key, which authenticates
// with private_key_jwt client assertions.
package machineenrollment

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"
)

const (
	apiVersion              = "2024-10-15"
	enrollmentsPath         = "/hidden/machines/enrollments"
	enrollmentType          = "machine_enrollment"
	jsonAPIContentType      = "application/vnd.api+json"
	maxResponseBodySize     = 64 << 10
	methodDeviceToken       = "device_token"
	methodFleetKey          = "fleet_key"
	clientAssertionTyp      = "client-key-assertion+jwt"
	fleetAuthorizationTyp   = "fleet-key-authorization+jwt"
	maxIdentifiers          = 32
	maxIdentifierValueChars = 256

	// DeviceTokenPrefix starts every device token.
	DeviceTokenPrefix = "sdt_"

	// retiredJoinKeyPrefix started the single-use join keys that device tokens replaced.
	retiredJoinKeyPrefix = "sjt_"
)

// ErrMalformedDeviceToken is returned for a device token that can't be one, before it is sent anywhere.
var ErrMalformedDeviceToken = errors.New("the device token is malformed: device tokens start with " + DeviceTokenPrefix)

// ErrRetiredJoinKey is returned for a retired join key (sjt_), which the enrollment service no
// longer accepts.
var ErrRetiredJoinKey = errors.New("join keys (" + retiredJoinKeyPrefix + "...) are no longer supported: ask an admin for a device token (" + DeviceTokenPrefix + "...) for this machine, or use a fleet key")

// ErrNoIdentifiers is returned when a fleet key enrollment has no valid identifier to name the machine with.
var ErrNoIdentifiers = errors.New("a fleet key enrollment needs between 1 and 32 machine identifiers, each of 1 to 256 characters")

// ErrOutcomeUnknown is returned when the enrollment request may have reached the service but its
// outcome could not be read: no response arrived, the response was a 2xx or 5xx whose body could not
// be read or used, or a 5xx that may follow an accepted enrollment. The service may have enrolled
// the machine.
var ErrOutcomeUnknown = errors.New("the outcome of the enrollment is unknown: the service may have enrolled the machine, a single-use device token (if one was used) may be spent, and an admin can check the machine's client and revoke it")

// Enrollment is the result of enrolling this device.
type Enrollment struct {
	MachineID string
	ClientID  string
	KeyID     string
	// Key is the machine client's private key, which the caller stores. It is the only credential
	// the machine needs from now on.
	Key *rsa.PrivateKey
}

// EnrollWithDeviceToken enrolls this machine with the single-use device token an admin issued for it,
// exchanging it for an OAuth client bound to a newly generated machine client key. It needs no
// device identity, so it works on any platform, and it enrolls the machine even if it is enrolled
// already. httpClient must not add authentication.
func EnrollWithDeviceToken(ctx context.Context, httpClient *http.Client, apiURL, deviceToken string, now time.Time) (Enrollment, error) {
	if strings.HasPrefix(deviceToken, retiredJoinKeyPrefix) {
		return Enrollment{}, ErrRetiredJoinKey
	}
	if !strings.HasPrefix(deviceToken, DeviceTokenPrefix) || len(deviceToken) == len(DeviceTokenPrefix) {
		return Enrollment{}, ErrMalformedDeviceToken
	}

	// The device token is a bearer secret that TLS and single use protect, so it is sent as is
	// instead of being signed into the assertion.
	return enroll(ctx, httpClient, apiURL, now, func(_ crypto.Signer, _ string) (string, string, error) {
		return methodDeviceToken, deviceToken, nil
	})
}

// EnrollWithFleetKey enrolls this machine with a fleet key, the P-256 key an admin registered and
// allowed for the machines of a fleet. The machine names itself by identifiers, which must be the
// ones an admin registered it with, and signs them with the fleet key. Like
// EnrollWithDeviceToken, it exchanges them for an OAuth client bound to a newly generated machine
// client key, but it enrolls only a machine that has no active client. httpClient must not add
// authentication.
func EnrollWithFleetKey(ctx context.Context, httpClient *http.Client, apiURL string, fleetKey *ecdsa.PrivateKey, identifiers []Identifier, now time.Time) (Enrollment, error) {
	if err := validateIdentifiers(identifiers); err != nil {
		return Enrollment{}, err
	}
	if fleetKey == nil || fleetKey.Curve != elliptic.P256() {
		return Enrollment{}, errors.New("the fleet key must be a P-256 key")
	}

	return enroll(ctx, httpClient, apiURL, now, func(clientKey crypto.Signer, audience string) (string, string, error) {
		authorization, err := fleetKeyAuthorization(fleetKey, clientKey, audience, identifiers, now)
		return methodFleetKey, authorization, err
	})
}

// enroll generates a client key and sends the enrollment that authorize makes for it. authorize
// returns the enrollment method and the authorization it carries, given the client key and the
// audience of the request.
func enroll(ctx context.Context, httpClient *http.Client, apiURL string, now time.Time, authorize func(clientKey crypto.Signer, audience string) (method, authorization string, err error)) (Enrollment, error) {
	if httpClient == nil {
		return Enrollment{}, errors.New("enrolling needs an http client")
	}
	key, err := GenerateKey()
	if err != nil {
		return Enrollment{}, err
	}

	url := apiURL + enrollmentsPath
	assertion, err := keyAssertion(key, url, now)
	if err != nil {
		return Enrollment{}, err
	}
	method, authorization, err := authorize(key, url)
	if err != nil {
		return Enrollment{}, err
	}

	// The server rejects any other attribute (additionalProperties: false).
	attributes := map[string]string{"method": method, "assertion": assertion, "authorization": authorization}
	res, err := postEnrollment(ctx, httpClient, url, attributes)
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{MachineID: res.MachineID, ClientID: res.ClientID, KeyID: res.KeyID, Key: key}, nil
}

// keyAssertion proves the machine holds key: it is signed by key, carries its public key, and is
// addressed to the enrollment endpoint at audience.
func keyAssertion(key crypto.Signer, audience string, now time.Time) (string, error) {
	jwk, err := publicJWK(key.Public())
	if err != nil {
		return "", err
	}
	return signJWT(key, clientAssertionTyp, map[string]any{"jwk": jwk}, map[string]any{
		"aud": audience,
		"iat": now.Unix(),
	})
}

type enrollmentResult struct {
	MachineID string `json:"machine_id"`
	ClientID  string `json:"client_id"`
	KeyID     string `json:"key_id"`
}

func postEnrollment(ctx context.Context, httpClient *http.Client, url string, attributes map[string]string) (enrollmentResult, error) {
	req := map[string]any{"data": map[string]any{
		"type":       enrollmentType,
		"attributes": attributes,
	}}
	body, err := json.Marshal(req)
	if err != nil {
		return enrollmentResult{}, fmt.Errorf("failed encoding enrollment: %w", err)
	}

	var res struct {
		Data struct {
			Attributes enrollmentResult `json:"attributes"`
		} `json:"data"`
	}
	if err = doJSONAPI(ctx, httpClient, http.MethodPost, url, string(body), http.StatusCreated, &res); err != nil {
		return enrollmentResult{}, fmt.Errorf("failed enrolling machine: %w", err)
	}
	if res.Data.Attributes.ClientID == "" {
		return enrollmentResult{}, fmt.Errorf("%w: enrollment response is missing the client_id", ErrOutcomeUnknown)
	}
	return res.Data.Attributes, nil
}

// mayHaveEnrolled reports whether a status leaves the outcome unknown: any 2xx is an acceptance, and
// a 5xx, such as a gateway timeout, may follow one. Every other status is a definite rejection.
func mayHaveEnrolled(status int) bool {
	return status/100 == 2 || status >= http.StatusInternalServerError
}

// doJSONAPI sends a JSON:API request and decodes the response into out, or returns the
// EnrollmentError the server sent.
func doJSONAPI(ctx context.Context, httpClient *http.Client, method, url, body string, want int, out any) error {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	// WroteRequest fires when the request has been handed to the connection, which may be before
	// the final flush, so it tells that the request may have reached the service, not that it did.
	var mayHaveReached atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			mayHaveReached.Store(true)
		}
	}})
	req, err := http.NewRequestWithContext(ctx, method, url+"?version="+apiVersion, reqBody)
	if err != nil {
		return fmt.Errorf("failed building request: %w", err)
	}
	req.Header.Set("Accept", jsonAPIContentType)
	if body != "" {
		req.Header.Set("Content-Type", jsonAPIContentType)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		if mayHaveReached.Load() {
			return fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
		}
		return err
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBodySize))
	if err != nil {
		if mayHaveEnrolled(res.StatusCode) {
			return fmt.Errorf("%w: failed reading the %d response: %w", ErrOutcomeUnknown, res.StatusCode, err)
		}
		return fmt.Errorf("%s %s returned %d but reading its response failed: %w", method, req.URL.Path, res.StatusCode, err)
	}
	if res.StatusCode != want {
		unexpected := newEnrollmentError(method, req.URL.Path, res.StatusCode, data)
		if mayHaveEnrolled(res.StatusCode) {
			return fmt.Errorf("%w: %w", ErrOutcomeUnknown, unexpected)
		}
		return unexpected
	}
	if err = json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: failed decoding response: %w", ErrOutcomeUnknown, err)
	}
	return nil
}
