package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	AUTH_TYPE_TOKEN                = "token"
	AUTH_TYPE_PAT                  = "pat"
	CACHED_PAT_KEY_PREFIX          = "cached_pat"
	CACHED_PAT_IS_VALID_KEY_PREFIX = "cached_pat_is_valid"
	CONFIG_KEY_TOKEN               = "api"      // the snyk config key for api token
	CONFIG_KEY_ENDPOINT            = "endpoint" // the snyk config key for api endpoint
	PAT_REGEX                      = `(snyk_(?:uat|sat))\.([a-z0-9]{8}\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)`
)

// Claims represents the structure of the PATs claims, it does not represent all the claims; only the ones we need
type Claims struct {
	// Hostname PAT is valid for
	Hostname string `json:"h"`
}

var _ Authenticator = (*tokenAuthenticator)(nil)

type tokenAuthenticator struct {
	tokenFunc func() string
}

func NewTokenAuthenticator(tokenFunc func() string) Authenticator {
	return &tokenAuthenticator{
		tokenFunc: tokenFunc,
	}
}

func (t *tokenAuthenticator) Authenticate() error {
	return nil
}

func (t *tokenAuthenticator) AddAuthenticationHeader(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil")
	}

	token := t.tokenFunc()
	if len(token) > 0 {
		request.Header.Set("Authorization", token)
		request.Header.Set("Session-Token", token)
	}

	return nil
}

func (t *tokenAuthenticator) IsSupported() bool {
	return true
}

func IsAuthTypeToken(token string) bool {
	if _, uuidErr := uuid.Parse(token); uuidErr == nil {
		return true
	}
	return false
}

func IsAuthTypePAT(token string) bool {
	// e.g. snyk_uat.1a2b3c4d.mySuperSecret_Token-Value.aChecksum_123-Value
	return regexp.MustCompile(fmt.Sprintf("^%s$", PAT_REGEX)).MatchString(token)
}

// extractClaimsFromPAT accepts a raw PAT string and returns the PAT claims
// differs from the implementation in oauth.go as Snyk PATs do not strictly follow the JWT spec
func extractClaimsFromPAT(raw string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid number of segments: %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var c Claims
	if err = json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &c, nil
}

func GetApiUrlFromPAT(pat string) (string, error) {
	claims, err := extractClaimsFromPAT(pat)
	if err != nil {
		return "", err
	}

	hostname := claims.Hostname
	if len(hostname) == 0 {
		return "", fmt.Errorf("hostname is empty")
	}

	if !strings.HasPrefix(hostname, "http") {
		hostname = fmt.Sprintf("https://%s", hostname)
	}

	return hostname, nil
}
