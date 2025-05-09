package auth

import (
	"fmt"
	"net/http"
)

const (
	CONFIG_KEY_PAT_TOKEN string = "INTERNAL_PAT_TOKEN_STORAGE"
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
	return nil
}

func (t *patAuthenticator) AddAuthenticationHeader(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil")
	}

	token := t.patFunc()
	if len(token) > 0 {
		value := fmt.Sprint("Bearer ", token)
		request.Header.Set("Authorization", value)
		request.Header.Set("Session-Token", value)
	}

	return nil
}

func (t *patAuthenticator) IsSupported() bool {
	return true
}
