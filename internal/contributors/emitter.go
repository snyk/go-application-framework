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

// Outcomes of [Emitter.Emit].
var (
	ErrNotAGitRepository = errors.New("not a git repository")
	ErrNoContributors    = errors.New("no contributors in the contributor window")
	ErrCollect           = errors.New("collect contributors")
	ErrSubmit            = errors.New("submit contributors")
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
	now    func() time.Time
}

// NewEmitter returns an Emitter that reports contributors of a repository, sending
// requests over httpClient to the API configured in config.
func NewEmitter(httpClient *http.Client, config configuration.Configuration, logger *zerolog.Logger) (*Emitter, error) {
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
		now:    time.Now,
	}, nil
}

// Emit reports the repository's current contributors against item, returning how
// many it collected.
//
// Every outcome other than a successful emission is returned as an error.
// A canceled context surfaces wrapped in [ErrCollect] or [ErrSubmit].
func (e *Emitter) Emit(ctx context.Context, repoPath string, orgID uuid.UUID, item Item) (int, error) {
	if err := item.validate(); err != nil {
		return 0, err
	}

	contributors, err := collectContributors(ctx, repoPath, e.now())
	if errors.Is(err, ErrNotAGitRepository) {
		return 0, err
	}
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrCollect, err)
	}
	if len(contributors) == 0 {
		return 0, ErrNoContributors
	}

	if err := e.ingest.SubmitContributors(ctx, orgID, item.EntityType, item.EntityID, contributors); err != nil {
		return len(contributors), fmt.Errorf("%w: %w", ErrSubmit, err)
	}

	return len(contributors), nil
}
