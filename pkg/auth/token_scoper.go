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

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

//go:generate go tool github.com/golang/mock/mockgen -source=token_scoper.go -destination ../mocks/token_scoper.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/auth/

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	// maxErrorResponseBytes bounds how much of a failed exchange response is read into the error.
	maxErrorResponseBytes = 1 << 20

	metaKeyOAuthError            = "error"
	metaKeyOAuthErrorDescription = "error_description"
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
	subjectToken, err := refreshedAccessToken(ctx, b.config)
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
	defer func(Body io.ReadCloser) { _ = Body.Close() }(req.Body)

	res, err := httpClient.Do(req)
	if err != nil {
		return "", cli.NewTokenScoperError("token exchange request failed", snyk_errors.WithCause(err))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(res.Body, maxErrorResponseBytes))
		return "", exchangeResponseError(res.StatusCode, body, readErr)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
		return "", cli.NewTokenScoperError("failed to decode token exchange response", snyk_errors.WithCause(err))
	}
	if tokenResponse.AccessToken == "" {
		return "", cli.NewTokenScoperError("token exchange response did not contain an access token")
	}

	return tokenResponse.AccessToken, nil
}

func exchangeResponseError(status int, body []byte, readErr error) error {
	detail := fmt.Sprintf("token exchange failed with status %d", status)
	var options []snyk_errors.Option
	if readErr != nil {
		options = append(options, snyk_errors.WithCause(readErr))
	} else {
		options = oauthErrorOptions(body)
	}
	return cli.NewTokenScoperError(detail, options...)
}

// oauthErrorOptions keeps only the RFC 6749 error fields from a failed exchange body. The
// body is never stored as a whole because the server may echo the submitted tokens back.
func oauthErrorOptions(body []byte) []snyk_errors.Option {
	var oauthErr struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &oauthErr); err != nil {
		return nil
	}
	var options []snyk_errors.Option
	if oauthErr.Error != "" {
		options = append(options, snyk_errors.WithMeta(metaKeyOAuthError, oauthErr.Error))
	}
	if oauthErr.ErrorDescription != "" {
		options = append(options, snyk_errors.WithMeta(metaKeyOAuthErrorDescription, oauthErr.ErrorDescription))
	}
	return options
}

// refreshedAccessToken goes through the authenticator so that an expired token is refreshed and
// persisted exactly as it is for regular requests.
func refreshedAccessToken(ctx context.Context, config configuration.Configuration) (string, error) {
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.GetString(configuration.API_URL), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for oauth token refresh: %w", err)
	}
	if err = authenticator.AddAuthenticationHeader(req); err != nil {
		return "", snyk.NewUnauthorisedError("failed to refresh stored oauth token", snyk_errors.WithCause(err))
	}
	authHeader := req.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid or no authorization header")
	}
	return strings.Trim(parts[1], " "), nil
}

// RevokeToken implements [BearerTokenScoper].
// Revocation is not supported yet, so it always returns an error rather than reporting success.
func (b bearerTokenScoperImpl) RevokeToken(ctx context.Context, token string) error {
	return snyk.NewNotImplementedError("token revocation is not implemented")
}

func NewBearerTokenScoper(config configuration.Configuration, httpClient *http.Client) BearerTokenScoper {
	return bearerTokenScoperImpl{
		config:     config,
		httpClient: httpClient,
	}
}
