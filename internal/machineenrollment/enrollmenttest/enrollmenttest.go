// Package enrollmenttest provides test doubles for machine enrollment: a certificate authority that
// issues device identities, an in-memory keychain holding them, and a fake API server that
// implements the enrollment, token and tenant endpoints and independently verifies everything the
// client signs.
package enrollmenttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/snyk/go-application-framework/internal/machineenrollment"
)

// CA is a device management certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *rsa.PrivateKey
}

// NewCA returns a new self-signed CA named name.
func NewCA(t *testing.T, name string) *CA {
	t.Helper()
	key := rsaKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, key: key}
}

// IdentityOption changes the certificate CA.Issue issues.
type IdentityOption func(*x509.Certificate)

// WithValidity sets the certificate's validity period.
func WithValidity(notBefore, notAfter time.Time) IdentityOption {
	return func(c *x509.Certificate) { c.NotBefore, c.NotAfter = notBefore, notAfter }
}

// WithExtKeyUsage sets the certificate's extended key usages.
func WithExtKeyUsage(usages ...x509.ExtKeyUsage) IdentityOption {
	return func(c *x509.Certificate) { c.ExtKeyUsage = usages }
}

// Issue issues a client authentication identity with the given common name and an RSA key.
func (ca *CA) Issue(t *testing.T, commonName string, opts ...IdentityOption) *Identity {
	t.Helper()
	key := rsaKey(t)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, opt := range opts {
		opt(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Identity{Signer: key, cert: cert}
}

// Identity is an in-memory device identity.
type Identity struct {
	crypto.Signer
	cert *x509.Certificate
	// Closed reports whether Close was called.
	Closed bool
}

func (i *Identity) Certificate() *x509.Certificate { return i.cert }
func (i *Identity) Close()                         { i.Closed = true }

// Keychain is an in-memory keychain.
type Keychain struct {
	Identities []*Identity
	Info       machineenrollment.DeviceInfo
}

// Identity returns the first identity issued by one of acceptedIssuers that is currently valid.
func (k *Keychain) Identity(acceptedIssuers [][]byte) (machineenrollment.DeviceIdentity, error) {
	for _, id := range k.Identities {
		for _, issuer := range acceptedIssuers {
			if string(issuer) == string(id.cert.RawIssuer) && time.Now().Before(id.cert.NotAfter) {
				return id, nil
			}
		}
	}
	return nil, machineenrollment.ErrNoIdentity
}

func (k *Keychain) DeviceInfo() machineenrollment.DeviceInfo { return k.Info }

// Server is a fake API serving the enrollment, token and tenant endpoints.
type Server struct {
	*httptest.Server
	ca *CA

	mu sync.Mutex
	// RejectEnrollment, when set, is the detail of a 403 returned instead of enrolling.
	RejectEnrollment string
	// Attestations holds the claims of every accepted device attestation.
	Attestations []map[string]any
	// Tenants is what GET /rest/tenants returns.
	Tenants []machineenrollment.Tenant
	// TokenRequests counts accepted token requests.
	TokenRequests int
	nonces        map[string]bool // nonce -> used
	clients       map[string]*ecdsa.PublicKey
	jtis          map[string]bool
	tokens        map[string]string // access token -> client id
	next          int
}

// NewServer starts a fake API whose enrollment endpoint accepts identities issued by ca.
func NewServer(t *testing.T, ca *CA) *Server {
	t.Helper()
	s := &Server{
		ca:      ca,
		nonces:  map[string]bool{},
		clients: map[string]*ecdsa.PublicKey{},
		jtis:    map[string]bool{},
		tokens:  map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hidden/machines/enrollment_challenges", s.challenge)
	mux.HandleFunc("POST /hidden/machines/attested_enrollments", s.enroll)
	mux.HandleFunc("POST /oauth2/token", s.token)
	mux.HandleFunc("GET /rest/tenants", s.listTenants)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// RegisterClient makes the token endpoint accept client assertions for clientID signed by key.
func (s *Server) RegisterClient(clientID string, key *ecdsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientID] = key
}

// ClientKey returns the key clientID enrolled with.
func (s *Server) ClientKey(clientID string) *ecdsa.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[clientID]
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("version") == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce) //nolint:errcheck // crypto/rand never fails
	n := base64.RawURLEncoding.EncodeToString(nonce)
	s.mu.Lock()
	s.nonces[n] = false
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{
		"id": "challenge", "type": "machine_enrollment_challenge",
		"attributes": map[string]any{
			"nonce":            n,
			"expires_at":       time.Now().Add(2 * time.Minute).Format(time.RFC3339),
			"accepted_issuers": []string{base64.StdEncoding.EncodeToString(s.ca.Cert.RawSubject)},
		},
	}})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Assertion   string `json:"assertion"`
				Attestation string `json:"attestation"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Data.Type != "machine_attested_enrollment" {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RejectEnrollment != "" {
		writeError(w, http.StatusForbidden, s.RejectEnrollment)
		return
	}

	key, jkt, nonce, err := s.verifyAssertion(req.Data.Attributes.Assertion, s.URL+r.URL.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "assertion: "+err.Error())
		return
	}
	claims, err := s.verifyAttestation(req.Data.Attributes.Attestation, s.URL+r.URL.Path, nonce, jkt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "attestation: "+err.Error())
		return
	}
	if used, ok := s.nonces[nonce]; !ok || used {
		writeError(w, http.StatusUnauthorized, "The challenge is not valid.")
		return
	}
	s.nonces[nonce] = true

	s.next++
	clientID := fmt.Sprintf("client-%d", s.next)
	s.clients[clientID] = key
	s.Attestations = append(s.Attestations, claims)
	writeJSON(w, http.StatusCreated, map[string]any{"data": map[string]any{
		"id": clientID, "type": "machine_attested_enrollment",
		"attributes": map[string]any{"machine_id": fmt.Sprintf("machine-%d", s.next), "client_id": clientID, "key_id": jkt},
	}})
}

func (s *Server) verifyAssertion(token, audience string) (*ecdsa.PublicKey, string, string, error) {
	header, claims, err := decodeJWT(token)
	if err != nil {
		return nil, "", "", err
	}
	if header["alg"] != "ES256" {
		return nil, "", "", errors.New("alg must be ES256")
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
	nonce, _ := claims["nonce"].(string) //nolint:errcheck // checked below
	if nonce == "" {
		return nil, "", "", errors.New("nonce is missing")
	}
	return key, jkt, nonce, nil
}

func (s *Server) verifyAttestation(token, audience, nonce, jkt string) (map[string]any, error) {
	header, claims, err := decodeJWT(token)
	if err != nil {
		return nil, err
	}
	if header["alg"] != "RS256" {
		return nil, errors.New("alg must be RS256")
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return nil, errors.New("x5c header is missing")
	}
	leafB64, _ := x5c[0].(string) //nolint:errcheck // an empty string fails to parse
	der, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, err
	}
	if err = VerifyJWT(token, leaf.PublicKey); err != nil {
		return nil, err
	}
	if claims["aud"] != audience || claims["nonce"] != nonce {
		return nil, errors.New("aud or nonce does not match")
	}
	cnf, _ := claims["cnf"].(map[string]any) //nolint:errcheck // a missing cnf fails below
	if cnf["jkt"] != jkt {
		return nil, errors.New("cnf.jkt is not the assertion key's thumbprint")
	}
	return claims, nil
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

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	accessToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, known := s.tokens[accessToken]; !ok || !known {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	data := []map[string]any{}
	for _, t := range s.Tenants {
		data = append(data, map[string]any{"id": t.ID, "type": "tenant", "attributes": map[string]any{"name": t.Name}})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
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

func parseJWK(jwk map[string]any) (*ecdsa.PublicKey, string, error) {
	x, _ := jwk["x"].(string) //nolint:errcheck // checked by decoding
	y, _ := jwk["y"].(string) //nolint:errcheck // checked by decoding
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["d"] != nil {
		return nil, "", errors.New("jwk must be a P-256 public key")
	}
	xb, errX := base64.RawURLEncoding.DecodeString(x)
	yb, errY := base64.RawURLEncoding.DecodeString(y)
	if errX != nil || errY != nil || len(xb) != 32 || len(yb) != 32 {
		return nil, "", errors.New("jwk has malformed coordinates")
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, xb...), yb...))
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(fmt.Appendf(nil, `{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y))
	return key, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
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
