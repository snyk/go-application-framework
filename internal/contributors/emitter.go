// Package contributors reports the git contributors for a repository and the
// associated entity under test to the Contributors ingest API.
package contributors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Item identifies the entity that contributors are attributed to.
type Item struct {
	EntityType contributors_ingest.EntityType
	EntityID   string
}

func (i Item) validate() error {
	if !i.EntityType.Valid() {
		return fmt.Errorf("unsupported entity type %q", i.EntityType)
	}
	if i.EntityID == "" {
		return errors.New("entity ID is required")
	}
	return nil
}

// ingestClient is the slice of contributors_ingest.Client that Emitter needs.
type ingestClient interface {
	SubmitContributors(
		ctx context.Context,
		orgID uuid.UUID,
		entityType contributors_ingest.EntityType,
		entityID string,
		contributors []contributors_ingest.Contributor,
	) error
}

// Emitter synchronously collects and reports contributors for a given repository.
type Emitter struct {
	ingest ingestClient
	logger *zerolog.Logger
	now    func() time.Time
}

// New returns an Emitter that reports contributors of a repository, sending
// requests over httpClient to the API configured in config.
func New(httpClient *http.Client, config configuration.Configuration, logger *zerolog.Logger) (*Emitter, error) {
	if httpClient == nil || config == nil || logger == nil {
		return nil, errors.New("http client, configuration, and logger are required")
	}

	ingest, err := contributors_ingest.NewClient(
		httpClient,
		config.GetString(configuration.API_URL),
		logger,
	)
	if err != nil {
		return nil, err
	}

	return &Emitter{
		ingest: ingest,
		logger: logger,
		now:    time.Now,
	}, nil
}

// Emit reports the repository's current contributors against item.
//
// It returns nil when there is no git repository or no commits in the contributor
// window.
func (e *Emitter) Emit(ctx context.Context, repoPath string, orgID uuid.UUID, item Item) error {
	if orgID == uuid.Nil {
		return errors.New("org ID is required")
	}
	if err := item.validate(); err != nil {
		return err
	}

	contributors, err := collectContributors(ctx, repoPath, e.now())
	if err != nil {
		return fmt.Errorf("collect contributors: %w", err)
	}
	if len(contributors) == 0 {
		e.logger.Debug().Str("repo_path", repoPath).Msg("contributor billing: no contributors to report")
		return nil
	}

	if err := e.ingest.SubmitContributors(ctx, orgID, item.EntityType, item.EntityID, contributors); err != nil {
		return fmt.Errorf("emit contributor billing: %w", err)
	}

	e.logger.Debug().
		Int("contributors", len(contributors)).
		Str("entity_id", item.EntityID).
		Msg("contributor billing: emitted")

	return nil
}
