package machineenrollment_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/machineenrollment/enrollmenttest"
)

func TestClientAssertion(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	now := time.Now()

	assertion, err := machineenrollment.ClientAssertion(key, "client-1", "https://api.example.com/oauth2/token", now)
	require.NoError(t, err)

	require.NoError(t, enrollmenttest.VerifyJWT(assertion, &key.PublicKey))
	header, claims := enrollmenttest.DecodeJWT(t, assertion)
	assert.Equal(t, "RS256", header["alg"])
	assert.NotEmpty(t, header["kid"])
	assert.Equal(t, "client-1", claims["iss"])
	assert.Equal(t, "client-1", claims["sub"])
	assert.Equal(t, "https://api.example.com/oauth2/token", claims["aud"])
	assert.NotEmpty(t, claims["jti"])
	assert.InDelta(t, now.Add(5*time.Minute).Unix(), claims["exp"], 1)
	assert.NotContains(t, claims, "iat", "iat is left out so clock skew can't get the assertion rejected")

	another, err := machineenrollment.ClientAssertion(key, "client-1", "https://api.example.com/oauth2/token", now)
	require.NoError(t, err)
	_, anotherClaims := enrollmenttest.DecodeJWT(t, another)
	assert.NotEqual(t, claims["jti"], anotherClaims["jti"])
}

func newFleetKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func serials(values ...string) []machineenrollment.Identifier {
	var ids []machineenrollment.Identifier
	for _, v := range values {
		ids = append(ids, machineenrollment.Identifier{Type: machineenrollment.IdentifierTypeSerialNumber, Value: v})
	}
	return ids
}

func TestEnrollWithDeviceToken(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueDeviceToken(srv.RegisterMachine())

	e, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, token, time.Now())
	require.NoError(t, err)

	assert.Equal(t, "machine-1", e.MachineID)
	assert.Equal(t, "client-1", e.ClientID)
	assert.NotEmpty(t, e.KeyID)
	require.NotNil(t, e.Key)
	assert.True(t, e.Key.PublicKey.Equal(srv.ClientKey(e.ClientID)), "the client is bound to the returned key")

	// A device token is single-use.
	_, err = machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, token, time.Now())
	require.Error(t, err)
	var enrollErr *machineenrollment.EnrollmentError
	require.ErrorAs(t, err, &enrollErr)
	assert.Equal(t, http.StatusUnauthorized, enrollErr.Status)
	assert.Contains(t, err.Error(), "The device token is not valid.")
}

func TestEnrollWithDeviceTokenReEnrollsAnEnrolledMachine(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	machineID := srv.RegisterMachine()

	first, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, srv.IssueDeviceToken(machineID), time.Now())
	require.NoError(t, err)
	second, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, srv.IssueDeviceToken(machineID), time.Now())
	require.NoError(t, err)

	assert.Equal(t, first.MachineID, second.MachineID)
	assert.NotEqual(t, first.ClientID, second.ClientID)
	assert.Nil(t, srv.ClientKey(first.ClientID), "the previous client stops working")
}

func TestEnrollWithDeviceTokenRevokedByANewerToken(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	machineID := srv.RegisterMachine()
	old := srv.IssueDeviceToken(machineID)
	srv.IssueDeviceToken(machineID)

	_, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, old, time.Now())
	var enrollErr *machineenrollment.EnrollmentError
	require.ErrorAs(t, err, &enrollErr)
	assert.Equal(t, http.StatusUnauthorized, enrollErr.Status)
}

func TestEnrollWithDeviceTokenRejectsMalformedTokens(t *testing.T) {
	// Nothing listens here, so a request would fail with a different error.
	const apiURL = "http://127.0.0.1:1"
	for _, token := range []string{"", "sdt_", "not-a-device-token"} {
		_, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, apiURL, token, time.Now())
		assert.ErrorIs(t, err, machineenrollment.ErrMalformedDeviceToken, token)
	}
}

func TestEnrollWithDeviceTokenRejectsRetiredJoinKeys(t *testing.T) {
	const apiURL = "http://127.0.0.1:1"
	_, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, apiURL, "sjt_abc", time.Now())
	require.ErrorIs(t, err, machineenrollment.ErrRetiredJoinKey)
	assert.Contains(t, err.Error(), "device token")
	assert.Contains(t, err.Error(), "sdt_")
}

func TestEnrollWithDeviceTokenRequestBody(t *testing.T) {
	var gotPath, gotQuery, gotType string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotType = r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type")
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusCreated)
		_, werr := w.Write([]byte(`{"data":{"id":"c","type":"machine_enrollment","attributes":{"machine_id":"m","client_id":"c","key_id":"k"}}}`))
		assert.NoError(t, werr)
	}))
	defer srv.Close()

	e, err := machineenrollment.EnrollWithDeviceToken(context.Background(), srv.Client(), srv.URL, "sdt_abc", time.Now())
	require.NoError(t, err)
	assert.Equal(t, "m", e.MachineID)

	assert.Equal(t, "/hidden/machines/enrollments", gotPath)
	assert.Equal(t, "version=2024-10-15", gotQuery)
	assert.Equal(t, "application/vnd.api+json", gotType)

	// Exactly {"data":{"type":"machine_enrollment","attributes":{"method":...,"assertion":...,"authorization":...}}}.
	require.Len(t, gotBody, 1)
	data, ok := gotBody["data"].(map[string]any)
	require.True(t, ok)
	require.Len(t, data, 2)
	assert.Equal(t, "machine_enrollment", data["type"])
	attrs, ok := data["attributes"].(map[string]any)
	require.True(t, ok)
	require.Len(t, attrs, 3)
	assert.Equal(t, "device_token", attrs["method"])
	assert.Equal(t, "sdt_abc", attrs["authorization"])
	assertion, ok := attrs["assertion"].(string)
	require.True(t, ok)
	assert.Len(t, strings.Split(assertion, "."), 3)
}

// roundTripFunc captures requests sent through an http.Client.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// capturingClient returns an http.Client that records the body of the requests it sends.
func capturingClient(body *[]byte) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var err error
		if *body, err = io.ReadAll(r.Body); err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(*body))
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type capturedAttributes struct {
	Method        string `json:"method"`
	Assertion     string `json:"assertion"`
	Authorization string `json:"authorization"`
}

func decodeAttributes(t *testing.T, body []byte) capturedAttributes {
	t.Helper()
	var req struct {
		Data struct {
			Attributes capturedAttributes `json:"attributes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	return req.Data.Attributes
}

func TestEnrollWithDeviceTokenSendsClientKeyAssertion(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	var body []byte

	e, err := machineenrollment.EnrollWithDeviceToken(context.Background(), capturingClient(&body), srv.URL, srv.IssueDeviceToken(srv.RegisterMachine()), time.Now())
	require.NoError(t, err)

	header, claims := enrollmenttest.DecodeJWT(t, decodeAttributes(t, body).Assertion)
	assert.Equal(t, "RS256", header["alg"])
	assert.Equal(t, "client-key-assertion+jwt", header["typ"])
	jwk, ok := header["jwk"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "RSA", jwk["kty"])
	assert.NotEmpty(t, jwk["n"])
	assert.NotEmpty(t, jwk["e"])
	assert.NotContains(t, jwk, "d")
	assert.Equal(t, srv.URL+"/hidden/machines/enrollments", claims["aud"])
	assert.Contains(t, claims, "iat")
	assert.NotContains(t, claims, "join_token", "the device token travels in authorization, unsigned")
	assert.GreaterOrEqual(t, e.Key.N.BitLen(), 2048)
}

func TestEnrollWithFleetKey(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	fleetKey := newFleetKey(t)
	machineID := srv.RegisterMachine("SERIAL-1", "BOARD-1")
	srv.AllowFleetKey(&fleetKey.PublicKey, machineID)
	var body []byte

	// One of the machine's serial numbers is enough, and unknown identifier types are ignored.
	ids := append(serials("BOARD-1"), machineenrollment.Identifier{Type: "mac_address", Value: "00:1B:44:11:3A:B7"})
	e, err := machineenrollment.EnrollWithFleetKey(context.Background(), capturingClient(&body), srv.URL, fleetKey, ids, time.Now())
	require.NoError(t, err)

	assert.Equal(t, machineID, e.MachineID)
	assert.True(t, e.Key.PublicKey.Equal(srv.ClientKey(e.ClientID)))

	attrs := decodeAttributes(t, body)
	assert.Equal(t, "fleet_key", attrs.Method)
	header, claims := enrollmenttest.DecodeJWT(t, attrs.Authorization)
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "fleet-key-authorization+jwt", header["typ"])
	assert.NotEmpty(t, header["kid"])
	assert.Equal(t, srv.URL+"/hidden/machines/enrollments", claims["aud"])
	assert.Contains(t, claims, "iat")
	assert.Len(t, claims["identifiers"], 2)
	assert.Contains(t, claims["cnf"], "jkt")
	require.NoError(t, enrollmenttest.VerifyJWT(attrs.Authorization, &fleetKey.PublicKey))
}

func TestEnrollWithFleetKeyIsReusableByOtherMachines(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	fleetKey := newFleetKey(t)
	a, b := srv.RegisterMachine("A"), srv.RegisterMachine("B")
	srv.AllowFleetKey(&fleetKey.PublicKey, a, b)

	first, err := machineenrollment.EnrollWithFleetKey(context.Background(), http.DefaultClient, srv.URL, fleetKey, serials("A"), time.Now())
	require.NoError(t, err)
	second, err := machineenrollment.EnrollWithFleetKey(context.Background(), http.DefaultClient, srv.URL, fleetKey, serials("B"), time.Now())
	require.NoError(t, err)

	assert.Equal(t, a, first.MachineID)
	assert.Equal(t, b, second.MachineID)
}

func TestEnrollWithFleetKeyErrors(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, srv *enrollmenttest.Server, fleetKey *ecdsa.PrivateKey)
		ids    []machineenrollment.Identifier
		want   error
		status int
	}{
		{
			name:   "machine not registered",
			setup:  func(_ *testing.T, srv *enrollmenttest.Server, fk *ecdsa.PrivateKey) { srv.AllowFleetKey(&fk.PublicKey) },
			ids:    serials("UNKNOWN"),
			want:   machineenrollment.ErrMachineNotRegistered,
			status: http.StatusForbidden,
		},
		{
			name: "identifiers ambiguous",
			setup: func(_ *testing.T, srv *enrollmenttest.Server, fk *ecdsa.PrivateKey) {
				srv.AllowFleetKey(&fk.PublicKey, srv.RegisterMachine("A"), srv.RegisterMachine("B"))
			},
			ids:    serials("A", "B"),
			want:   machineenrollment.ErrIdentifiersAmbiguous,
			status: http.StatusForbidden,
		},
		{
			name: "machine deprovisioned",
			setup: func(_ *testing.T, srv *enrollmenttest.Server, fk *ecdsa.PrivateKey) {
				id := srv.RegisterMachine("A")
				srv.AllowFleetKey(&fk.PublicKey, id)
				srv.DeprovisionMachine(id)
			},
			ids:    serials("A"),
			want:   machineenrollment.ErrMachineDeprovisioned,
			status: http.StatusForbidden,
		},
		{
			name: "machine enrolled",
			setup: func(t *testing.T, srv *enrollmenttest.Server, fk *ecdsa.PrivateKey) {
				t.Helper()
				id := srv.RegisterMachine("A")
				srv.AllowFleetKey(&fk.PublicKey, id)
				_, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, srv.IssueDeviceToken(id), time.Now())
				require.NoError(t, err)
			},
			ids:    serials("A"),
			want:   machineenrollment.ErrMachineEnrolled,
			status: http.StatusConflict,
		},
		{
			name:   "unknown fleet key",
			setup:  func(*testing.T, *enrollmenttest.Server, *ecdsa.PrivateKey) {},
			ids:    serials("A"),
			status: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := enrollmenttest.NewServer(t)
			fleetKey := newFleetKey(t)
			tt.setup(t, srv, fleetKey)

			_, err := machineenrollment.EnrollWithFleetKey(context.Background(), http.DefaultClient, srv.URL, fleetKey, tt.ids, time.Now())

			require.Error(t, err)
			var enrollErr *machineenrollment.EnrollmentError
			require.ErrorAs(t, err, &enrollErr)
			assert.Equal(t, tt.status, enrollErr.Status)
			if tt.want != nil {
				assert.ErrorIs(t, err, tt.want)
				for _, other := range []error{machineenrollment.ErrMachineNotRegistered, machineenrollment.ErrIdentifiersAmbiguous, machineenrollment.ErrMachineDeprovisioned, machineenrollment.ErrMachineEnrolled} {
					if !errors.Is(tt.want, other) {
						assert.NotErrorIs(t, err, other)
					}
				}
			}
		})
	}
}

func TestEnrollWithFleetKeyNotRegisteredListsIdentifiers(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	fleetKey := newFleetKey(t)
	srv.AllowFleetKey(&fleetKey.PublicKey)

	_, err := machineenrollment.EnrollWithFleetKey(context.Background(), http.DefaultClient, srv.URL, fleetKey, serials("C02XK1JHJG5J"), time.Now())

	var enrollErr *machineenrollment.EnrollmentError
	require.ErrorAs(t, err, &enrollErr)
	assert.Equal(t, machineenrollment.CodeMachineNotRegistered, enrollErr.Code)
	assert.Equal(t, serials("C02XK1JHJG5J"), enrollErr.Identifiers)
	assert.Contains(t, err.Error(), "ask an admin to register the machine")
}

func TestEnrollWithFleetKeyRejectsBadInput(t *testing.T) {
	const apiURL = "http://127.0.0.1:1"
	fleetKey := newFleetKey(t)
	tooMany := make([]machineenrollment.Identifier, 33)
	for i := range tooMany {
		tooMany[i] = serials("S")[0]
	}
	for name, ids := range map[string][]machineenrollment.Identifier{
		"none":      nil,
		"too many":  tooMany,
		"empty":     serials(""),
		"too long":  serials(strings.Repeat("x", 257)),
		"nul":       serials("a\x00b"),
		"no type":   {{Value: "A"}},
		"no values": {{Type: "serial_number"}},
	} {
		_, err := machineenrollment.EnrollWithFleetKey(context.Background(), http.DefaultClient, apiURL, fleetKey, ids, time.Now())
		assert.ErrorIs(t, err, machineenrollment.ErrNoIdentifiers, name)
	}

	_, err := machineenrollment.EnrollWithFleetKey(context.Background(), http.DefaultClient, apiURL, nil, serials("A"), time.Now())
	assert.Error(t, err)
}

func TestEnrollRejectsRequestsThatDontConformToTheSpec(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	post := func(body string) int {
		res, err := http.Post(srv.URL+"/hidden/machines/enrollments?version=2024-10-15", "application/vnd.api+json", strings.NewReader(body))
		require.NoError(t, err)
		defer func() { assert.NoError(t, res.Body.Close()) }()
		return res.StatusCode
	}

	assert.Equal(t, http.StatusBadRequest, post(`{"data":{"type":"machine_enrollment","attributes":{"assertion":"a"}}}`), "the old body")
	assert.Equal(t, http.StatusBadRequest, post(`{"data":{"type":"machine_enrollment","attributes":{"method":"bogus","assertion":"a","authorization":"b"}}}`))
	assert.Equal(t, http.StatusBadRequest, post(`{"data":{"type":"machine_enrollment","attributes":{"method":"device_token","assertion":"a","authorization":"b","machine_id":"m"}}}`))
	assert.Equal(t, http.StatusBadRequest, post(`{"data":{"type":"machine_enrollment","attributes":{"method":"device_token","assertion":"a","authorization":"b"}}}`), "an assertion that isn't a JWT")
}
