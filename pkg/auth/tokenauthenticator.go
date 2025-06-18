package auth

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/google/uuid"
)

const (
	AUTH_TYPE_TOKEN                = "token"
	AUTH_TYPE_PAT                  = "pat"
	CACHED_PAT_KEY_PREFIX          = "cached_pat"
	CACHED_PAT_IS_VALID_KEY_PREFIX = "cached_pat_is_valid"
	CONFIG_KEY_TOKEN               = "api"      // the snyk config key for api token
	CONFIG_KEY_ENDPOINT            = "endpoint" // the snyk config key for api endpoint
)

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
	patRegex := `^snyk_(?:uat|sat)\.[a-z0-9]{8}\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$`
	if matched, err := regexp.MatchString(patRegex, token); err == nil && matched {
		return matched
	}
	return false
}
