package contributors

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestNew_BuildsEmitterFromConfiguration(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	logger := zerolog.Nop()

	emitter, err := New(http.DefaultClient, config, &logger)
	require.NoError(t, err)

	assert.NotNil(t, emitter.ingest)
	assert.NotNil(t, emitter.now)
}

func TestNew_RejectsUnusableAPIURL(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "not-a-url")
	logger := zerolog.Nop()

	_, err := New(http.DefaultClient, config, &logger)
	assert.Error(t, err)
}

func TestNew_RequiresHTTPClientConfigurationAndLogger(t *testing.T) {
	config := configuration.NewWithOpts()
	logger := zerolog.Nop()

	_, err := New(nil, config, &logger)
	assert.Error(t, err)

	_, err = New(http.DefaultClient, nil, &logger)
	assert.Error(t, err)

	_, err = New(http.DefaultClient, config, nil)
	assert.Error(t, err)
}

func TestEmit_SendsCollectedContributors(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)},
		commit{email: "bob@example.com", when: now.AddDate(0, 0, -10)},
	)

	ingest := &fakeIngest{}
	emitter := newTestEmitter(t, ingest, now)

	err := emitter.Emit(t.Context(), repo.path(), testOrgID, Item{
		EntityType: contributors_ingest.EntityTypeProject,
		EntityID:   "22222222-2222-2222-2222-222222222222",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, ingest.calls)
	assert.Equal(t, testOrgID, ingest.orgID)
	assert.Equal(t, contributors_ingest.EntityTypeProject, ingest.entityType)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", ingest.entityID)
	assert.Equal(t, []string{"alice@example.com", "bob@example.com"}, emails(ingest.contributors))
}

func TestEmit_SkipsIngestWhenThereAreNoContributors(t *testing.T) {
	tests := map[string]string{
		"not a git repository": t.TempDir(),
		"repository with no commits in window": newTestRepo(t, commit{
			email: "old@example.com",
			when:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		}).path(),
	}

	for name, repo := range tests {
		t.Run(name, func(t *testing.T) {
			ingest := &fakeIngest{}
			emitter := newTestEmitter(t, ingest, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))

			assert.NoError(t, emitter.Emit(t.Context(), repo, testOrgID, validItem()))
			assert.Zero(t, ingest.calls, "nothing to report is not a failure, but must not POST")
		})
	}
}

func TestEmit_RejectsInvalidInput(t *testing.T) {
	tests := map[string]struct {
		orgID uuid.UUID
		item  Item
	}{
		"missing org ID": {
			orgID: uuid.Nil,
			item:  validItem(),
		},
		"missing entity ID": {
			orgID: testOrgID,
			item:  Item{EntityType: contributors_ingest.EntityTypeProject},
		},
		"missing entity type": {
			orgID: testOrgID,
			item:  Item{EntityID: "22222222-2222-2222-2222-222222222222"},
		},
		"unknown entity type": {
			orgID: testOrgID,
			item:  Item{EntityType: "organization", EntityID: "22222222-2222-2222-2222-222222222222"},
		},
	}

	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ingest := &fakeIngest{}
			emitter := newTestEmitter(t, ingest, now)

			assert.Error(t, emitter.Emit(t.Context(), repo.path(), tc.orgID, tc.item))
			assert.Zero(t, ingest.calls, "invalid input must be caught before any git or network work")
		})
	}
}

func TestEmit_ReturnsIngestFailure(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})

	wantErr := errors.New("boom")
	ingest := &fakeIngest{err: wantErr}
	emitter := newTestEmitter(t, ingest, now)

	err := emitter.Emit(t.Context(), repo.path(), testOrgID, validItem())
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestEmit_SkipsIngestWhenContextIsCancelled(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})

	ingest := &fakeIngest{}
	emitter := newTestEmitter(t, ingest, now)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := emitter.Emit(ctx, repo.path(), testOrgID, validItem())
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, ingest.calls, "a canceled emit must not POST")
}

var testOrgID = uuid.MustParse("11111111-1111-1111-1111-111111111111")

// fakeIngest records what Emit asked it to send.
type fakeIngest struct {
	calls        int
	orgID        uuid.UUID
	entityType   contributors_ingest.EntityType
	entityID     string
	contributors []contributors_ingest.Contributor
	err          error
}

func (f *fakeIngest) SubmitContributors(
	_ context.Context,
	orgID uuid.UUID,
	entityType contributors_ingest.EntityType,
	entityID string,
	contributors []contributors_ingest.Contributor,
) error {
	f.calls++
	f.orgID = orgID
	f.entityType = entityType
	f.entityID = entityID
	f.contributors = contributors
	return f.err
}

// newTestEmitter builds an Emitter over repoPath with a fake ingest client.
func newTestEmitter(t *testing.T, ingest *fakeIngest, now time.Time) *Emitter {
	t.Helper()

	logger := zerolog.Nop()
	return &Emitter{
		ingest: ingest,
		logger: &logger,
		now:    func() time.Time { return now },
	}
}

func validItem() Item {
	return Item{
		EntityType: contributors_ingest.EntityTypeProject,
		EntityID:   "22222222-2222-2222-2222-222222222222",
	}
}

func emails(contributors []contributors_ingest.Contributor) []string {
	result := make([]string, 0, len(contributors))
	for _, c := range contributors {
		result = append(result, c.Email)
	}
	return result
}
