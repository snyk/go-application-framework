package auth

import (
	"fmt"
	"net/http"
	"regexp"
)

const (
	AUTH_TYPE_PAT = "pat"
)

var _ Authenticator = (*patAuthenticator)(nil)

type patAuthenticator struct {
	patFunc func() string
}

func NewPATAuthenticator(patFunc func() string) Authenticator {
	return &patAuthenticator{
		patFunc: patFunc,
	}
}

func (t *patAuthenticator) Authenticate() error {
	// use PAT to call the PAT API endpoint to validate PAT && get back the supported Snyk endpoint
	return nil
}

func (t *patAuthenticator) AddAuthenticationHeader(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil")
	}

	token := t.patFunc()
	if len(token) > 0 {
		request.Header.Set("Authorization", token)
		request.Header.Set("Session-Token", token)
	}

	return nil
}

func (t *patAuthenticator) IsSupported() bool {
	return true
}

func IsAuthTypePAT(token string) bool {
	// e.g. snyk_uat.1a2b3c4d.mySuperSecret_Token-Value.aChecksum_123-Value
	// this will also need to return authTypePAT when using `snyk auth <PAT>`
	patRegex := `^snyk_(?:uat|sat)\.[a-z0-9]{8}\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$`
	if matched, err := regexp.MatchString(patRegex, token); err == nil && matched {
		return matched
	}
	return false
}
