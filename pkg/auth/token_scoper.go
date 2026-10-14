package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

type BearerTokenScoper interface {
	// GetScopedBearerToken returns a bearer token without any prefix for usage
	GetToken(ctx context.Context, scopes []string, ttl time.Duration) (string, error)
	// RevokeScopedBearerToken revokes the given token
	RevokeToken(ctx context.Context, token string) error
}

var _ = BearerTokenScoper(bearerTokenScoperImpl{})

type bearerTokenScoperImpl struct {
	config     configuration.Configuration
	httpClient *http.Client
}

// GetScopedBearerToken implements [BearerTokenScoper].
// It exchanges the configured access token for a token limited to the given scopes (RFC 8693).
func (b bearerTokenScoperImpl) GetToken(ctx context.Context, scopes []string, ttl time.Duration) (string, error) {
	subjectToken := b.config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
	if subjectToken == "" {
		return "", fmt.Errorf("no user authentication available to exchange a scoped token")
	}

	// Client credentials if configured, otherwise the OAuth client ID of the user login flow.
	conf := getOAuthConfigurationClientCredentials(getOAuthConfiguration(b.config))
	conf.AuthStyle = oauth2.AuthStyleInParams
	conf.Scopes = scopes
	conf.EndpointParams = url.Values{
		"grant_type":           {grantTypeTokenExchange},
		"subject_token":        {subjectToken},
		"subject_token_type":   {tokenTypeAccessToken},
		"requested_token_type": {tokenTypeAccessToken},
	}
	if ttl > 0 {
		conf.EndpointParams.Set("ttl", strconv.FormatInt(int64(ttl.Seconds()), 10))
	}

	if b.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, b.httpClient)
	}
	token, err := conf.TokenSource(ctx).Token()
	if err != nil {
		return "", fmt.Errorf("failed to exchange token for scoped token: %w", err)
	}

	return token.AccessToken, nil
}

// RevokeScopedBearerToken implements [BearerTokenScoper].
func (b bearerTokenScoperImpl) RevokeToken(ctx context.Context, token string) error {
	return nil
}

func NewBearerTokenScoper(config configuration.Configuration, httpClient *http.Client) bearerTokenScoperImpl {
	return bearerTokenScoperImpl{
		config:     config,
		httpClient: httpClient,
	}
}
