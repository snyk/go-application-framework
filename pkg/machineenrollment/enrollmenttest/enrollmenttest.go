// Package enrollmenttest provides a test double for the enrollment service: a fake API server
// that implements the enrollment (by device token and by fleet key) and token endpoints as the
// service's enrollment spec defines them, and independently verifies everything the client signs.
package enrollmenttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xeipuuv/gojsonschema"

	"github.com/snyk/go-application-framework/pkg/machineenrollment"
)

const (
	assertionTyp    = "client-key-assertion+jwt"
	fleetAuthTyp    = "fleet-key-authorization+jwt"
	assertionMaxAge = 5 * time.Minute
	assertionSkew   = 30 * time.Second
)

// requestSchema mirrors the request body of the service's enrollment API contract.
const requestSchema = `{
  "type": "object", "required": ["data"], "additionalProperties": false,
  "properties": {"data": {
    "type": "object", "required": ["type", "attributes"], "additionalProperties": false,
    "properties": {
      "type": {"enum": ["machine_enrollment"]},
      "attributes": {"oneOf": [
        {"type": "object", "required": ["method", "assertion", "authorization"], "additionalProperties": false,
         "properties": {"method": {"enum": ["device_token"]}, "assertion": {"type": "string", "maxLength": 8192}, "authorization": {"type": "string", "maxLength": 256}}},
        {"type": "object", "required": ["method", "assertion", "authorization"], "additionalProperties": false,
         "properties": {"method": {"enum": ["fleet_key"]}, "assertion": {"type": "string", "maxLength": 8192}, "authorization": {"type": "string", "maxLength": 49152}}}
      ]}
    }}}}`

type machine struct {
	id            string
	serials       []string
	deprovisioned bool
	clientID      string // the active client, or ""
}

type deviceToken struct {
	machine *machine
	used    bool
	revoked bool
}

// Server is a fake API serving the enrollment and token endpoints.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// TokenRequests counts accepted token requests.
	TokenRequests int
	machines      []*machine
	deviceTokens  map[string]*deviceToken
	fleetKeys     map[string]fleetKey // by thumbprint
	enrolledKeys  map[string]bool     // client key thumbprints
	clients       map[string]*rsa.PublicKey
	jtis          map[string]bool
	tokens        map[string]string // access token -> client id
	next          int
}

type fleetKey struct {
	pub      *ecdsa.PublicKey
	machines []*machine
}

// NewServer starts a fake API implementing the enrollment and token endpoints.
func NewServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		deviceTokens: map[string]*deviceToken{},
		fleetKeys:    map[string]fleetKey{},
		enrolledKeys: map[string]bool{},
		clients:      map[string]*rsa.PublicKey{},
		jtis:         map[string]bool{},
		tokens:       map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hidden/machines/enrollments", s.enroll)
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

// RegisterMachine registers a machine with serial numbers, as an admin does, and returns its id.
func (s *Server) RegisterMachine(serialNumbers ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := &machine{id: fmt.Sprintf("machine-%d", len(s.machines)+1), serials: serialNumbers}
	s.machines = append(s.machines, m)
	return m.id
}

// DeprovisionMachine retires a machine: it can't enroll again, with any join material.
func (s *Server) DeprovisionMachine(machineID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.machineByID(machineID).deprovisioned = true
}

// IssueDeviceToken returns a new single-use device token for a registered machine, as an admin gets.
// Like the service, it revokes the machine's earlier device tokens.
func (s *Server) IssueDeviceToken(machineID string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := machineenrollment.DeviceTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.machineByID(machineID)
	for _, dt := range s.deviceTokens {
		if dt.machine == m {
			dt.revoked = true
		}
	}
	s.deviceTokens[token] = &deviceToken{machine: m}
	return token
}

// AllowFleetKey registers the public half of a fleet key and allows it for the machines.
func (s *Server) AllowFleetKey(pub *ecdsa.PublicKey, machineIDs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kid := thumbprintEC(pub)
	fk := s.fleetKeys[kid]
	fk.pub = pub
	for _, id := range machineIDs {
		fk.machines = append(fk.machines, s.machineByID(id))
	}
	s.fleetKeys[kid] = fk
}

// ClientKey returns the key clientID enrolled with.
func (s *Server) ClientKey(clientID string) *rsa.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[clientID]
}

// ClientCount returns how many clients are registered, whether active or not.
func (s *Server) ClientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

func (s *Server) machineByID(id string) *machine {
	for _, m := range s.machines {
		if m.id == id {
			return m
		}
	}
	panic("enrollmenttest: unknown machine " + id)
}

// parseRequest checks the request against the spec and returns its attributes, or writes the error
// response and returns false.
func parseRequest(w http.ResponseWriter, r *http.Request) (attrs requestAttributes, ok bool) {
	if r.URL.Query().Get("version") != "2024-10-15" {
		writeError(w, http.StatusBadRequest, "", "version is missing or unsupported")
		return attrs, false
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/vnd.api+json" {
		writeError(w, http.StatusBadRequest, "", "content type must be application/vnd.api+json, not "+ct)
		return attrs, false
	}
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, "", "malformed request")
		return attrs, false
	}
	result, err := gojsonschema.Validate(gojsonschema.NewStringLoader(requestSchema), gojsonschema.NewBytesLoader(raw))
	if err != nil || !result.Valid() {
		writeError(w, http.StatusBadRequest, "", "request does not conform to the spec: "+fmt.Sprint(result.Errors()))
		return attrs, false
	}
	var req enrollmentRequest
	if err = json.Unmarshal(raw, &req); err != nil {
		writeError(w, http.StatusBadRequest, "", "malformed request")
		return attrs, false
	}
	return req.Data.Attributes, true
}

type requestAttributes struct {
	Method        string `json:"method"`
	Assertion     string `json:"assertion"`
	Authorization string `json:"authorization"`
}

type enrollmentRequest struct {
	Data struct {
		Attributes requestAttributes `json:"attributes"`
	} `json:"data"`
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	attrs, ok := parseRequest(w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	audience := s.URL + r.URL.Path
	key, jkt, err := s.verifyAssertion(attrs.Assertion, audience)
	if err != nil {
		writeError(w, http.StatusBadRequest, "", "invalid client key assertion: "+err.Error())
		return
	}

	var m *machine
	var dt *deviceToken
	switch attrs.Method {
	case "device_token":
		dt = s.deviceTokens[attrs.Authorization]
		if dt == nil || dt.used || dt.revoked || dt.machine.deprovisioned {
			writeError(w, http.StatusUnauthorized, "", "The device token is not valid.")
			return
		}
		m = dt.machine
	case "fleet_key":
		var ok bool
		if m, ok = s.authorizeFleetKey(w, attrs.Authorization, audience, jkt); !ok {
			return
		}
	}
	if s.enrolledKeys[jkt] {
		writeError(w, http.StatusConflict, "", "The client key has enrolled before.")
		return
	}

	// Enrolling replaces the machine's client, if it has one: only a device token gets here then.
	delete(s.clients, m.clientID)
	if dt != nil {
		dt.used = true
	}
	s.enrolledKeys[jkt] = true
	s.next++
	clientID := fmt.Sprintf("client-%d", s.next)
	m.clientID = clientID
	s.clients[clientID] = key
	w.Header().Set("Location", "/rest/machines/self?version=2024-10-15")
	writeJSON(w, http.StatusCreated, map[string]any{
		"jsonapi": map[string]any{"version": "1.0"},
		"data": map[string]any{
			"id": clientID, "type": "machine_enrollment",
			"attributes": map[string]any{"machine_id": m.id, "client_id": clientID, "key_id": jkt},
		},
		"links": map[string]any{"self": r.URL.Path},
	})
}

// authorizeFleetKey verifies a fleet key authorization and finds the machine it names, or writes the
// error response and returns false.
func (s *Server) authorizeFleetKey(w http.ResponseWriter, authorization, audience, clientJKT string) (*machine, bool) {
	header, claims, err := decodeJWT(authorization)
	if err != nil {
		writeError(w, http.StatusBadRequest, "", "invalid fleet key authorization: "+err.Error())
		return nil, false
	}
	if header["alg"] != "ES256" || header["typ"] != fleetAuthTyp {
		writeError(w, http.StatusBadRequest, "", "invalid fleet key authorization: alg must be ES256 and typ "+fleetAuthTyp)
		return nil, false
	}
	// The signature is verified before the claims are checked or any machine is looked up.
	fk, ok := s.fleetKeys[fmt.Sprint(header["kid"])]
	if !ok || VerifyJWT(authorization, fk.pub) != nil {
		writeError(w, http.StatusUnauthorized, "", "The fleet key is not valid.")
		return nil, false
	}

	identifiers, err := checkFleetClaims(claims, audience, clientJKT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "", "invalid fleet key authorization: "+err.Error())
		return nil, false
	}

	var found []*machine
	for _, m := range fk.machines {
		if slices.ContainsFunc(m.serials, func(serial string) bool { return slices.Contains(identifiers, serial) }) && !slices.Contains(found, m) {
			found = append(found, m)
		}
	}
	switch {
	case len(found) == 0:
		looked := make([]map[string]string, 0, len(identifiers))
		for _, v := range identifiers {
			looked = append(looked, map[string]string{"type": "serial_number", "value": v})
		}
		writeErrorMeta(w, http.StatusForbidden, machineenrollment.CodeMachineNotRegistered,
			"No machine this fleet key allows has any of these identifiers. Ask an admin to register the machine and allow the key for it.",
			map[string]any{"identifiers": looked})
	case len(found) > 1:
		writeError(w, http.StatusForbidden, machineenrollment.CodeIdentifiersAmbiguous, "The identifiers name more than one machine this fleet key allows.")
	case found[0].deprovisioned:
		writeError(w, http.StatusForbidden, machineenrollment.CodeMachineDeprovisioned, "The machine is deprovisioned.")
	case found[0].clientID != "":
		writeError(w, http.StatusConflict, machineenrollment.CodeMachineEnrolled, "The machine is enrolled already. Ask an admin for a device token to enroll it again.")
	default:
		return found[0], true
	}
	return nil, false
}

// checkFleetClaims checks the claims of a fleet key authorization and returns its serial numbers.
func checkFleetClaims(claims map[string]any, audience, clientJKT string) ([]string, error) {
	if err := checkAudienceAndAge(claims, audience); err != nil {
		return nil, err
	}
	if cnf, _ := claims["cnf"].(map[string]any); cnf["jkt"] != clientJKT { //nolint:errcheck // a missing cnf fails the comparison
		return nil, errors.New("cnf.jkt is not the client key's thumbprint")
	}
	return knownIdentifiers(claims["identifiers"])
}

// knownIdentifiers returns the values of the serial_number identifiers, ignoring other types, and
// fails unless there are 1 to 32 identifiers and one is of a known type.
func knownIdentifiers(v any) ([]string, error) {
	list, _ := v.([]any) //nolint:errcheck // checked by the length
	if len(list) == 0 || len(list) > 32 {
		return nil, errors.New("identifiers must have between 1 and 32 entries")
	}
	var serials []string
	for _, item := range list {
		id, _ := item.(map[string]any) //nolint:errcheck // an invalid entry has no type
		if id["type"] != "serial_number" {
			continue
		}
		value, _ := id["value"].(string) //nolint:errcheck // checked below
		if value == "" || len([]rune(value)) > 256 || strings.ContainsRune(value, 0) {
			return nil, errors.New("an identifier has a bad value")
		}
		serials = append(serials, value)
	}
	if len(serials) == 0 {
		return nil, errors.New("no identifier is of a known type")
	}
	return serials, nil
}

func checkAudienceAndAge(claims map[string]any, audience string) error {
	if claims["aud"] != audience {
		return fmt.Errorf("aud is %v, want %s", claims["aud"], audience)
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		return errors.New("iat is missing")
	}
	issued := time.Unix(int64(iat), 0)
	if time.Since(issued) > assertionMaxAge || time.Until(issued) > assertionSkew {
		return errors.New("iat is stale or in the future")
	}
	return nil
}

// verifyAssertion verifies a self-signed RS256 client key assertion (the only algorithm the OAuth
// token server accepts) addressed to audience and returns its key and the key's thumbprint.
func (s *Server) verifyAssertion(token, audience string) (*rsa.PublicKey, string, error) {
	header, claims, err := decodeJWT(token)
	if err != nil {
		return nil, "", err
	}
	if header["alg"] != "RS256" {
		return nil, "", errors.New("signing method " + fmt.Sprint(header["alg"]) + " is invalid")
	}
	if header["typ"] != assertionTyp {
		return nil, "", fmt.Errorf("typ is %v, want %s", header["typ"], assertionTyp)
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		return nil, "", errors.New("jwk header is missing")
	}
	key, jkt, err := parseJWK(jwk)
	if err != nil {
		return nil, "", err
	}
	if err = VerifyJWT(token, key); err != nil {
		return nil, "", err
	}
	if err = checkAudienceAndAge(claims, audience); err != nil {
		return nil, "", err
	}
	return key, jkt, nil
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

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeErrorMeta(w, status, code, detail, nil)
}

func writeErrorMeta(w http.ResponseWriter, status int, code, detail string, meta map[string]any) {
	e := map[string]any{"status": fmt.Sprint(status), "detail": detail}
	if code != "" {
		e["code"] = code
	}
	if meta != nil {
		e["meta"] = meta
	}
	writeJSON(w, status, map[string]any{"jsonapi": map[string]any{"version": "1.0"}, "errors": []map[string]any{e}})
}

// thumbprintEC returns the RFC 7638 thumbprint of a P-256 key.
func thumbprintEC(pub *ecdsa.PublicKey) string {
	b, err := pub.Bytes()
	if err != nil || pub.Curve != elliptic.P256() {
		panic("enrollmenttest: not a P-256 key")
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(b[1:33]), base64.RawURLEncoding.EncodeToString(b[33:]))
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeOAuthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code}) //nolint:errcheck // test server
}
