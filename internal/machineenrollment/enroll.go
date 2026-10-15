package machineenrollment

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	apiVersion               = "2024-10-15"
	challengesPath           = "/hidden/machines/enrollment_challenges"
	attestedEnrollmentsPath  = "/hidden/machines/attested_enrollments"
	joinTokenEnrollmentsPath = "/hidden/machines/enrollments"
	challengeType            = "machine_enrollment_challenge"
	attestedEnrollmentType   = "machine_attested_enrollment"
	joinTokenEnrollmentType  = "machine_enrollment"
	jsonAPIContentType       = "application/vnd.api+json"
	maxResponseBodySize      = 64 << 10

	// JoinTokenPrefix starts every join token.
	JoinTokenPrefix = "sjt_"
)

// ErrMalformedJoinToken is returned for a join token that can't be one, before it is sent anywhere.
var ErrMalformedJoinToken = errors.New("the join token is malformed: join tokens start with " + JoinTokenPrefix)

// Enrollment is the result of enrolling this device.
type Enrollment struct {
	MachineID string
	ClientID  string
	KeyID     string
	// Key is the machine client's private key, which the caller stores. It is the only credential
	// the machine needs from now on.
	Key *rsa.PrivateKey
}

// Enroll enrolls this device with the API at apiURL. It fetches a challenge, signs it with both the
// keychain identity issued by an issuer the server accepts and a newly generated machine client key,
// and exchanges the two signatures for an OAuth client bound to the new key. httpClient must not
// add authentication; enrolling is how the machine gets its credential.
func Enroll(ctx context.Context, httpClient *http.Client, apiURL string, keychain Keychain, now time.Time) (Enrollment, error) {
	c, err := requestChallenge(ctx, httpClient, apiURL)
	if err != nil {
		return Enrollment{}, err
	}

	identity, err := keychain.Identity(c.acceptedIssuers)
	if err != nil {
		return Enrollment{}, err
	}
	defer identity.Close()

	key, err := GenerateKey()
	if err != nil {
		return Enrollment{}, err
	}

	url := apiURL + attestedEnrollmentsPath
	assertion, err := keyAssertion(key, url, "nonce", c.nonce, now)
	if err != nil {
		return Enrollment{}, err
	}
	attestation, err := deviceAttestation(identity, keychain.DeviceInfo(), &key.PublicKey, url, c.nonce, now)
	if err != nil {
		return Enrollment{}, err
	}

	res, err := postEnrollment(ctx, httpClient, url, attestedEnrollmentType, map[string]string{"assertion": assertion, "attestation": attestation})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{MachineID: res.MachineID, ClientID: res.ClientID, KeyID: res.KeyID, Key: key}, nil
}

// EnrollWithJoinToken enrolls this machine with the single-use join token an admin issued for it,
// exchanging it for an OAuth client bound to a newly generated machine client key. It needs no
// device identity, so it works on any platform. httpClient must not add authentication.
func EnrollWithJoinToken(ctx context.Context, httpClient *http.Client, apiURL, joinToken string, now time.Time) (Enrollment, error) {
	if !strings.HasPrefix(joinToken, JoinTokenPrefix) || len(joinToken) == len(JoinTokenPrefix) {
		return Enrollment{}, ErrMalformedJoinToken
	}

	key, err := GenerateKey()
	if err != nil {
		return Enrollment{}, err
	}

	url := apiURL + joinTokenEnrollmentsPath
	assertion, err := keyAssertion(key, url, "join_token", joinToken, now)
	if err != nil {
		return Enrollment{}, err
	}

	res, err := postEnrollment(ctx, httpClient, url, joinTokenEnrollmentType, map[string]string{"assertion": assertion})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{MachineID: res.MachineID, ClientID: res.ClientID, KeyID: res.KeyID, Key: key}, nil
}

type challenge struct {
	nonce           string
	acceptedIssuers [][]byte
}

func requestChallenge(ctx context.Context, httpClient *http.Client, apiURL string) (challenge, error) {
	var res struct {
		Data struct {
			Attributes struct {
				Nonce           string   `json:"nonce"`
				AcceptedIssuers []string `json:"accepted_issuers"`
			} `json:"attributes"`
		} `json:"data"`
	}
	body := fmt.Sprintf(`{"data":{"type":%q}}`, challengeType)
	if err := doJSONAPI(ctx, httpClient, http.MethodPost, apiURL+challengesPath, body, http.StatusCreated, &res); err != nil {
		return challenge{}, fmt.Errorf("failed requesting enrollment challenge: %w", err)
	}

	attrs := res.Data.Attributes
	if attrs.Nonce == "" || len(attrs.AcceptedIssuers) == 0 {
		return challenge{}, errors.New("enrollment challenge is missing its nonce or accepted issuers")
	}
	c := challenge{nonce: attrs.Nonce}
	for _, issuer := range attrs.AcceptedIssuers {
		der, err := base64.StdEncoding.DecodeString(issuer)
		if err != nil {
			return challenge{}, fmt.Errorf("enrollment challenge has a malformed accepted issuer: %w", err)
		}
		c.acceptedIssuers = append(c.acceptedIssuers, der)
	}
	return c, nil
}

// keyAssertion proves the machine holds key: it is signed by key, carries its public key, and is
// addressed to the enrollment endpoint at audience. The claim named by name is what the machine
// enrolls with: the challenge nonce or the join token.
func keyAssertion(key *rsa.PrivateKey, audience, name, value string, now time.Time) (string, error) {
	jwk, err := publicJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return signJWT(key, map[string]any{"jwk": jwk}, map[string]any{
		"aud": audience,
		"iat": now.Unix(),
		name:  value,
	})
}

// deviceAttestation proves the machine holds the identity's private key, and binds the new machine
// client key to it through the key's thumbprint.
func deviceAttestation(identity DeviceIdentity, info DeviceInfo, clientKey crypto.PublicKey, audience, nonce string, now time.Time) (string, error) {
	jkt, err := thumbprint(clientKey)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"aud":   audience,
		"iat":   now.Unix(),
		"nonce": nonce,
		"cnf":   map[string]string{"jkt": jkt},
	}
	if info.UDID != "" {
		claims["udid"] = info.UDID
	}
	if info.Serial != "" {
		claims["serial"] = info.Serial
	}
	x5c := []string{base64.StdEncoding.EncodeToString(identity.Certificate().Raw)}
	return signJWT(identity, map[string]any{"x5c": x5c}, claims)
}

type enrollmentResult struct {
	MachineID string `json:"machine_id"`
	ClientID  string `json:"client_id"`
	KeyID     string `json:"key_id"`
}

func postEnrollment(ctx context.Context, httpClient *http.Client, url, resourceType string, attributes map[string]string) (enrollmentResult, error) {
	req := map[string]any{"data": map[string]any{
		"type":       resourceType,
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
		return enrollmentResult{}, errors.New("enrollment response is missing the client_id")
	}
	return res.Data.Attributes, nil
}

// doJSONAPI sends a JSON:API request and decodes the response into out, or returns the error
// details the server sent.
func doJSONAPI(ctx context.Context, httpClient *http.Client, method, url, body string, want int, out any) error {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
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
		return err
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("failed reading response: %w", err)
	}
	if res.StatusCode != want {
		return fmt.Errorf("%s %s returned %d%s", method, req.URL.Path, res.StatusCode, errorDetail(data))
	}
	if err = json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed decoding response: %w", err)
	}
	return nil
}

// errorDetail returns the detail of a JSON:API error response, prefixed for appending to an error
// message, or "" if it has none.
func errorDetail(body []byte) string {
	var res struct {
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &res) != nil {
		return ""
	}
	var details []string
	for _, e := range res.Errors {
		if e.Detail != "" {
			details = append(details, e.Detail)
		}
	}
	if len(details) == 0 {
		return ""
	}
	return ": " + strings.Join(details, "; ")
}
