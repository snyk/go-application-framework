package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type BearerTokenScoper interface {
	// GetScopedBearerToken returns a bearer token without any prefix for usage
	GetScopedBearerToken(ctx context.Context, scopes []string, ttl time.Duration) (string, error)
	// RevokeScopedBearerToken revokes the given token
	RevokeScopedBearerToken(ctx context.Context, token string) error
}

var _ = BearerTokenScoper(bearerTokenScoperImpl{})

type bearerTokenScoperImpl struct {
	config     configuration.Configuration
	httpClient *http.Client
}

// GetScopedBearerToken implements [BearerTokenScoper].
func (b bearerTokenScoperImpl) GetScopedBearerToken(ctx context.Context, claims []string, ttl time.Duration) (string, error) {
	panic("unimplemented")
}

// RevokeScopedBearerToken implements [BearerTokenScoper].
func (b bearerTokenScoperImpl) RevokeScopedBearerToken(ctx context.Context, token string) error {
	panic("unimplemented")
}

func NewBearerTokenScoper(config configuration.Configuration, httpClient *http.Client) bearerTokenScoperImpl {
	return bearerTokenScoperImpl{
		config:     config,
		httpClient: httpClient,
	}
}
