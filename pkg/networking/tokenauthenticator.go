package networking

import (
	"fmt"
	"net/http"
)

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

func (t *tokenAuthenticator) Authorize(request *http.Request) error {
	if request == nil {
		return fmt.Errorf("request must not be nil.")
	}

	token := t.tokenFunc()
	if len(token) > 0 {
		request.Header.Set("Authorization", token)
	}

	return nil
}

func (t *tokenAuthenticator) IsSupported() bool {
	return true
}
