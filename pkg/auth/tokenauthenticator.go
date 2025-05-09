package auth

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

const (
	AUTH_TYPE_TOKEN = "token"
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
