package machineenrollment

import (
	"context"
	"crypto/ecdsa"
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
	joinTokenEnrollmentsPath = "/hidden/machines/enrollments"
	joinTokenEnrollmentType  = "machine_enrollment"
	jsonAPIContentType       = "application/vnd.api+json"
	maxResponseBodySize      = 64 << 10

	// JoinTokenPrefix starts every join key.
	JoinTokenPrefix = "sjt_"
)

// ErrMalformedJoinToken is returned for a join key that can't be one, before it is sent anywhere.
var ErrMalformedJoinToken = errors.New("the join key is malformed: join keys start with " + JoinTokenPrefix)

// Enrollment is the result of enrolling this device.
type Enrollment struct {
	MachineID string
	ClientID  string
	KeyID     string
	// Key is the machine client's private key, which the caller stores. It is the only credential
	// the machine needs from now on.
	Key *ecdsa.PrivateKey
}

// EnrollWithJoinToken enrolls this machine with the single-use join key an admin issued for it,
// exchanging it for an OAuth client bound to a newly generated machine client key. It needs no
// device identity, so it works on any platform. httpClient must not add authentication.
//
// knownMachineID, when non-empty, is sent along with the enrollment request as the caller's own
// identifier for this machine, for the server to bind the enrollment to. The exact wire shape of
// this is unconfirmed against the real Machine Service at the time of writing; if the server
// ignores it, the machine id it returns is used instead.
func EnrollWithJoinToken(ctx context.Context, httpClient *http.Client, apiURL, joinToken, knownMachineID string, now time.Time) (Enrollment, error) {
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

	attributes := map[string]string{"assertion": assertion}
	if knownMachineID != "" {
		attributes["machine_id"] = knownMachineID
	}

	res, err := postEnrollment(ctx, httpClient, url, joinTokenEnrollmentType, attributes)
	if err != nil {
		return Enrollment{}, err
	}
	machineID := res.MachineID
	if machineID == "" {
		machineID = knownMachineID
	}
	return Enrollment{MachineID: machineID, ClientID: res.ClientID, KeyID: res.KeyID, Key: key}, nil
}

// keyAssertion proves the machine holds key: it is signed by key, carries its public key, and is
// addressed to the enrollment endpoint at audience. The claim named by name is what the machine
// enrolls with: the join key.
func keyAssertion(key *ecdsa.PrivateKey, audience, name, value string, now time.Time) (string, error) {
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
