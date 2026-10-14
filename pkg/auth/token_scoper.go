package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
// A positive ttl is passed to the server as the "ttl" query parameter in seconds.
func (b bearerTokenScoperImpl) GetToken(ctx context.Context, scopes []string, ttl time.Duration) (string, error) {
	subjectToken := b.config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
	if subjectToken == "" {
		return "", fmt.Errorf("no user authentication available to exchange a scoped token")
	}

	tokenUrl, err := url.Parse(getOAuthConfiguration(b.config).Endpoint.TokenURL)
	if err != nil {
		return "", fmt.Errorf("invalid token url: %w", err)
	}
	if ttl > 0 {
		query := tokenUrl.Query()
		query.Set("ttl", strconv.FormatInt(int64(ttl.Seconds()), 10))
		tokenUrl.RawQuery = query.Encode()
	}

	form := url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {tokenTypeAccessToken},
		"scope":              {strings.Join(scopes, " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenUrl.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := b.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if readErr != nil {
			return "", fmt.Errorf("token exchange failed with status %d: %w", res.StatusCode, readErr)
		}
		return "", fmt.Errorf("token exchange failed with status %d: %s", res.StatusCode, body)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode token exchange response: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("token exchange response did not contain an access token")
	}

	return tokenResponse.AccessToken, nil
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
