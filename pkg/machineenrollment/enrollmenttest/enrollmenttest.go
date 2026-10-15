// Package enrollmenttest provides a test double for the Machine Service: a fake API server that
// implements the join-key enrollment and token endpoints and independently verifies everything the
// client signs.
package enrollmenttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/machineenrollment"
)

// Server is a fake API serving the join-key enrollment and token endpoints.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// TokenRequests counts accepted token requests.
	TokenRequests int
	joinTokens    map[string]bool // join key -> used
	clients       map[string]*rsa.PublicKey
	jtis          map[string]bool
	tokens        map[string]string // access token -> client id
	next          int
}

// NewServer starts a fake API implementing the join-key enrollment and token endpoints.
func NewServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		joinTokens: map[string]bool{},
		clients:    map[string]*rsa.PublicKey{},
		jtis:       map[string]bool{},
		tokens:     map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hidden/machines/enrollments", s.enrollWithJoinToken)
	mux.HandleFunc("POST /oauth2/token", s.token)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// RegisterClient makes the token endpoint accept client assertions for clientID signed by key.
func (s *Server) RegisterClient(clientID string, key *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientID] = key
}

// IssueJoinToken returns a new single-use join key, as an admin registering a machine gets.
func (s *Server) IssueJoinToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) //nolint:errcheck // crypto/rand never fails
	token := "sjt_" + base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.joinTokens[token] = false
	return token
}

// ClientKey returns the key clientID enrolled with.
func (s *Server) ClientKey(clientID string) *rsa.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[clientID]
}

func (s *Server) enrollWithJoinToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Assertion string `json:"assertion"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Data.Type != "machine_enrollment" {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key, jkt, joinToken, err := s.verifyAssertion(req.Data.Attributes.Assertion, s.URL+r.URL.Path, "join_token")
	if err != nil {
		writeError(w, http.StatusBadRequest, "assertion: "+err.Error())
		return
	}
	if used, ok := s.joinTokens[joinToken]; !ok || used {
		writeError(w, http.StatusUnauthorized, "The join key is not valid.")
		return
	}
	s.joinTokens[joinToken] = true

	s.next++
	clientID := fmt.Sprintf("client-%d", s.next)
	s.clients[clientID] = key
	writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{
		"id": clientID, "type": "machine_enrollment",
		"attributes": map[string]any{"machine_id": fmt.Sprintf("machine-%d", s.next), "client_id": clientID, "key_id": jkt},
	}})
}

// verifyAssertion verifies a self-signed RS256 assertion (the only algorithm the machine identity service accepts) addressed to audience and returns its key,
// the key's thumbprint and the value of the claim named by credential.
func (s *Server) verifyAssertion(token, audience, credential string) (*rsa.PublicKey, string, string, error) {
	header, claims, err := decodeJWT(token)
	if err != nil {
		return nil, "", "", err
	}
	if header["alg"] != "RS256" {
		return nil, "", "", errors.New("signing method " + fmt.Sprint(header["alg"]) + " is invalid")
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		return nil, "", "", errors.New("jwk header is missing")
	}
	key, jkt, err := parseJWK(jwk)
	if err != nil {
		return nil, "", "", err
	}
	if err = VerifyJWT(token, key); err != nil {
		return nil, "", "", err
	}
	if claims["aud"] != audience {
		return nil, "", "", fmt.Errorf("aud is %v, want %s", claims["aud"], audience)
	}
	if _, ok := claims["iat"].(float64); !ok {
		return nil, "", "", errors.New("iat is missing")
	}
	value, _ := claims[credential].(string) //nolint:errcheck // checked below
	if value == "" {
		return nil, "", "", errors.New(credential + " is missing")
	}
	return key, jkt, value, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request")
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" ||
		r.PostForm.Get("client_assertion_type") != machineenrollment.ClientAssertionType ||
		r.PostForm.Has("client_secret") {
		writeOAuthError(w, "invalid_request")
		return
	}
	assertion := r.PostForm.Get("client_assertion")
	_, claims, err := decodeJWT(assertion)
	if err != nil {
		writeOAuthError(w, "invalid_client")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	clientID, _ := claims["sub"].(string) //nolint:errcheck // an unknown client is rejected below
	key := s.clients[clientID]
	jti, _ := claims["jti"].(string)  //nolint:errcheck // checked below
	exp, _ := claims["exp"].(float64) //nolint:errcheck // checked below
	if key == nil || VerifyJWT(assertion, key) != nil ||
		claims["iss"] != clientID || r.PostForm.Get("client_id") != clientID ||
		claims["aud"] != s.URL+"/oauth2/token" ||
		jti == "" || s.jtis[jti] || time.Unix(int64(exp), 0).Before(time.Now()) {
		writeOAuthError(w, "invalid_client")
		return
	}
	s.jtis[jti] = true
	s.TokenRequests++
	accessToken := fmt.Sprintf("token-%s-%d", clientID, s.TokenRequests)
	s.tokens[accessToken] = clientID
	writeJSON(w, http.StatusOK, map[string]any{"access_token": accessToken, "token_type": "bearer", "expires_in": 3600})
}

// VerifyJWT verifies a compact JWS signed with ES256 or RS256 by pub.
func VerifyJWT(token string, pub crypto.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if len(sig) != 64 {
			return errors.New("ES256 signature must be 64 bytes")
		}
		if !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("invalid ES256 signature")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig)
	default:
		return fmt.Errorf("unsupported key type %T", pub)
	}
}

// DecodeJWT returns the header and claims of a compact JWS without verifying it.
func DecodeJWT(t *testing.T, token string) (header, claims map[string]any) {
	t.Helper()
	header, claims, err := decodeJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	return header, claims
}

func decodeJWT(token string) (header, claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("not a compact JWS")
	}
	for i, out := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return nil, nil, err
		}
		if err = json.Unmarshal(raw, out); err != nil {
			return nil, nil, err
		}
	}
	return header, claims, nil
}

func parseJWK(jwk map[string]any) (*rsa.PublicKey, string, error) {
	n, _ := jwk["n"].(string) //nolint:errcheck // checked by decoding
	e, _ := jwk["e"].(string) //nolint:errcheck // checked by decoding
	if jwk["kty"] != "RSA" || jwk["d"] != nil {
		return nil, "", errors.New("jwk header must be an RSA key")
	}
	nb, errN := base64.RawURLEncoding.DecodeString(n)
	eb, errE := base64.RawURLEncoding.DecodeString(e)
	if errN != nil || errE != nil || len(nb) == 0 || len(eb) == 0 || len(eb) > 4 {
		return nil, "", errors.New("jwk header has a malformed modulus or exponent")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	if key.N.BitLen() < 2048 {
		return nil, "", errors.New("jwk header must be an RSA key of at least 2048 bits")
	}
	sum := sha256.Sum256(fmt.Appendf(nil, `{"e":%q,"kty":"RSA","n":%q}`, e, n))
	return key, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) //nolint:errcheck // test server
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"errors": []map[string]any{{"status": fmt.Sprint(status), "detail": detail}}})
}

func writeOAuthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code}) //nolint:errcheck // test server
}
