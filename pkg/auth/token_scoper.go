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

//go:generate go tool github.com/golang/mock/mockgen -source=token_scoper.go -destination ../mocks/token_scoper.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/auth/

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// BearerTokenScoper derives bearer tokens that are restricted to a subset of scopes from the
// current authentication, so that a caller can hand out a token with least privilege.
type BearerTokenScoper interface {
	// GetToken returns a bearer token, without any prefix, that is restricted to the given scopes.
	// A positive ttl requests a token lifetime; zero leaves the lifetime to the server's default.
	// An error is returned if no authentication is available or the server rejects the request.
	GetToken(ctx context.Context, scopes []string, ttl time.Duration) (string, error)
	// RevokeToken revokes the given token.
	RevokeToken(ctx context.Context, token string) error
}

var _ BearerTokenScoper = bearerTokenScoperImpl{}

type bearerTokenScoperImpl struct {
	config     configuration.Configuration
	httpClient *http.Client
}

// GetToken implements [BearerTokenScoper].
// It exchanges the configured access token for a token limited to the given scopes (RFC 8693).
// A positive ttl is passed to the server as the "ttl" query parameter in seconds.
func (b bearerTokenScoperImpl) GetToken(ctx context.Context, scopes []string, ttl time.Duration) (string, error) {
	subjectToken, err := b.getSubjectToken()
	if err != nil {
		return "", err
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

// getSubjectToken returns the access token to exchange: the configured bearer token, or else the
// access token stored by the OAuth login flow.
func (b bearerTokenScoperImpl) getSubjectToken() (string, error) {
	if bearerToken := b.config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN); bearerToken != "" {
		return bearerToken, nil
	}

	oauthToken, err := GetOAuthToken(b.config)
	if err != nil {
		return "", fmt.Errorf("failed to read stored oauth token: %w", err)
	}
	if oauthToken == nil || oauthToken.AccessToken == "" {
		return "", fmt.Errorf("no user authentication available to exchange a scoped token")
	}
	return oauthToken.AccessToken, nil
}

// RevokeToken implements [BearerTokenScoper].
// Revocation is not supported yet, so it always returns an error rather than reporting success.
func (b bearerTokenScoperImpl) RevokeToken(ctx context.Context, token string) error {
	return fmt.Errorf("token revocation is not implemented")
}

func NewBearerTokenScoper(config configuration.Configuration, httpClient *http.Client) BearerTokenScoper {
	return bearerTokenScoperImpl{
		config:     config,
		httpClient: httpClient,
	}
}
