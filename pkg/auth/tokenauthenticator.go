package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	snykError "github.com/snyk/error-catalog-golang-public/snyk"
	patAPI "github.com/snyk/go-application-framework/internal/api/personal_access_tokens/2024-03-19"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
)

const (
	AUTH_TYPE_TOKEN                = "token"
	AUTH_TYPE_PAT                  = "pat"
	CACHED_PAT_KEY_PREFIX          = "cached_pat"
	CACHED_PAT_IS_VALID_KEY_PREFIX = "cached_pat_is_valid"
	CONFIG_KEY_TOKEN               = "api"      // the snyk config key for api token
	CONFIG_KEY_ENDPOINT            = "endpoint" // the snyk config key for api endpoint
)

const (
	patAPIVersion = "2024-03-19"
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

type DeriveEndpointFn func(pat string, config configuration.Configuration, client *http.Client, regions []string) (string, error)

var _ DeriveEndpointFn = DeriveEndpointFromPAT

// DeriveEndpointFromPAT iterates a list of Snyk region URLs and tries to make an authenticated request to the Snyk PAT API
// on success, it will return the correct Snyk endpoint from the given PAT
func DeriveEndpointFromPAT(pat string, config configuration.Configuration, client *http.Client, regionUrls []string) (string, error) {
	var (
		err      error
		errs     error
		endpoint string
	)

	// include the default region as a fallback
	if !slices.Contains(regionUrls, constants.SNYK_DEFAULT_API_URL) {
		regionUrls = append(regionUrls, constants.SNYK_DEFAULT_API_URL)
	}

	for _, url := range regionUrls {
		endpoint, err = deriveEndpoint(pat, config, client, url)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		break
	}

	if errs != nil && len(endpoint) == 0 {
		return "", errs
	}

	return endpoint, nil
}

// deriveEndpoint makes an authenticated request to the Snyk PAT API and returns the correct Snyk endpoint from the given PAT
func deriveEndpoint(token string, config configuration.Configuration, client *http.Client, snykRegionUrl string) (string, error) {
	apiBaseUrl := snykRegionUrl
	if len(apiBaseUrl) == 0 {
		apiBaseUrl = constants.SNYK_DEFAULT_API_URL
	}

	if !strings.HasPrefix(apiBaseUrl, "hidden") {
		apiBaseUrl = fmt.Sprintf("%s/hidden", apiBaseUrl)
	}

	patApiClient, err := patAPI.NewClientWithResponses(apiBaseUrl, patAPI.WithHTTPClient(client))
	if err != nil {
		return "", fmt.Errorf("failed to create PAT API client: %w", err)
	}

	params := &patAPI.GetPatMetadataParams{
		Version: patAPIVersion,
	}

	reqEditors := []patAPI.RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
			return nil
		},
	}

	resp, err := patApiClient.GetPatMetadataWithResponse(context.Background(), params, reqEditors...)
	if err != nil {
		return "", snykError.NewUnauthorisedError("failed to validate PAT; either missing or invalid PAT")
	}

	if resp.StatusCode() != http.StatusOK {
		return "", snykError.NewUnauthorisedError(fmt.Sprintf("failed to get PAT metadata (status: %d): %s", resp.StatusCode(), string(resp.Body)))
	}

	patMetadataBody := resp.ApplicationvndApiJSON200
	if patMetadataBody == nil || patMetadataBody.Data.Attributes.Hostname == nil {
		return "", fmt.Errorf("failed to decode PAT metadata response or missing hostname")
	}

	hostname := *patMetadataBody.Data.Attributes.Hostname
	if hostname == "" {
		return "", fmt.Errorf("invalid empty hostname")
	}

	authHost, err := redirectAuthHost(hostname)
	if err != nil {
		return "", err
	}

	validHostRegex := config.GetString(CONFIG_KEY_ALLOWED_HOST_REGEXP)
	if isValid, err := utils.MatchesRegex(authHost, validHostRegex); err != nil || !isValid {
		return "", fmt.Errorf("invalid hostname: %s", authHost)
	}

	endpoint := fmt.Sprintf("https://%s", authHost)

	return endpoint, nil
}
