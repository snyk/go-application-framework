// Package contributors_ingest is a client for the Contributors ingest API,
// which records the git contributors associated with a Snyk entity.
package contributors_ingest

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	v20241015 "github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

const (
	// apiVersion is the resource version of the ingest endpoint this client targets.
	apiVersion = "2024-10-15"

	// requestTimeout is the timeout for one operation (all attempts included).
	requestTimeout = 10 * time.Second

	// requestAttempts is how many times a call tries to reach the ingest API.
	requestAttempts = 3

	// retryInterval is the initial backoff between those attempts.
	retryInterval = time.Second
)

// Client posts contributors to the ingest API.
type Client struct {
	api v20241015.ClientWithResponsesInterface
}

// NewClient returns a Client posting to the ingest endpoint under baseURL.
//
// httpClient is expected to already carry authentication. It is wrapped to add
// a retry policy. A nil logger disables retry logging.
func NewClient(httpClient *http.Client, baseURL string, logger *zerolog.Logger) (*Client, error) {
	server, err := serverURL(baseURL)
	if err != nil {
		return nil, err
	}

	api, err := v20241015.NewClientWithResponses(server, v20241015.WithHTTPClient(retrying(httpClient, logger)))
	if err != nil {
		return nil, fmt.Errorf("create contributors ingest client: %w", err)
	}

	return &Client{api: api}, nil
}

// SubmitContributors records contributors against one entity in one org.
func (c *Client) SubmitContributors(
	ctx context.Context,
	orgID uuid.UUID,
	entityType EntityType,
	entityID string,
	contributors []Contributor,
) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	resp, err := c.api.CreateContributingDevsWithApplicationVndAPIPlusJSONBodyWithResponse(
		ctx,
		orgID,
		&v20241015.CreateContributingDevsParams{Version: apiVersion},
		requestBody(entityType, entityID, contributors),
	)
	if err != nil {
		return fmt.Errorf("post contributors: %w", err)
	}
	if resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("post contributors: unexpected status %d", resp.StatusCode())
	}
	return nil
}

// Contributor is a single git author and the date of their most recent commit.
type Contributor struct {
	Email      string
	CommitDate time.Time
}

// EntityType is the kind of Snyk entity a set of contributors is attributed to.
type EntityType v20241015.ContributingDevsIngestAttributesContributorsEntityType

const (
	EntityTypeProject  = EntityType(v20241015.Project)
	EntityTypeTarget   = EntityType(v20241015.Target)
	EntityTypeRevision = EntityType(v20241015.Revision)
)

// Valid reports whether the entity type is one the ingest API accepts.
func (e EntityType) Valid() bool {
	switch e {
	case EntityTypeProject, EntityTypeTarget, EntityTypeRevision:
		return true
	default:
		return false
	}
}

// requestBody shapes contributors into the JSON:API document the ingest API expects.
func requestBody(entityType EntityType, entityID string, contributors []Contributor) v20241015.CreateContributingDevsRequestBody {
	// Always a non-nil slice: the API rejects a null contributors field.
	devs := make([]v20241015.Contributor, 0, len(contributors))
	for _, c := range contributors {
		devs = append(devs, v20241015.Contributor{
			Email:      c.Email,
			CommitDate: c.CommitDate.UTC(),
		})
	}

	var body v20241015.CreateContributingDevsRequestBody
	body.Data.Type = v20241015.ContributingDevs
	body.Data.Attributes = v20241015.ContributingDevsIngestAttributes{
		ContributorsEntityType: v20241015.ContributingDevsIngestAttributesContributorsEntityType(entityType),
		ContributorsEntityId:   entityID,
		Contributors:           devs,
	}
	return body
}

func serverURL(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("base URL %q must include scheme and host", baseURL)
	}
	return parsed.String(), nil
}

// retrying copies base and adds this client's retry policy, leaving the caller's
// client untouched.
func retrying(base *http.Client, logger *zerolog.Logger) *http.Client {
	client := &http.Client{}
	transport := http.DefaultTransport
	if base != nil {
		*client = *base
		if base.Transport != nil {
			transport = base.Transport
		}
	}
	if logger == nil {
		nop := zerolog.Nop()
		logger = &nop
	}

	// The retry middleware reads only this key, so the value is set here
	// rather than at the callsite of the requests.
	config := configuration.NewWithOpts()
	config.Set(middleware.ConfigurationKeyRequestAttempts, requestAttempts)

	client.Transport = middleware.NewRetryMiddleware(
		config, logger, transport, middleware.WithRetryInterval(retryInterval),
	)

	return client
}
