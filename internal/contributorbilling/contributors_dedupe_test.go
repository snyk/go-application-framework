package contributorbilling

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupeContributorsByEmail_KeepsLatestCommitDate(t *testing.T) {
	t.Parallel()

	older := time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 1, 20, 8, 0, 0, 0, time.UTC)

	got := dedupeContributorsByEmail([]Contributor{
		{Email: "alice@example.com", LatestCommitDate: older},
		{Email: "alice@example.com", LatestCommitDate: newer},
		{Email: "bob@example.com", LatestCommitDate: older},
	})

	require.Len(t, got, 2)
	assert.Equal(t, "alice@example.com", got[0].Email)
	assert.Equal(t, newer, got[0].LatestCommitDate)
	assert.Equal(t, "bob@example.com", got[1].Email)
	assert.Equal(t, older, got[1].LatestCommitDate)
}

func TestDedupeContributorsByEmail_CaseSensitive(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 1, 15, 8, 0, 0, 0, time.UTC)

	got := dedupeContributorsByEmail([]Contributor{
		{Email: "Alice@example.com", LatestCommitDate: when},
		{Email: "alice@example.com", LatestCommitDate: when},
	})

	require.Len(t, got, 2)
	assert.Equal(t, "Alice@example.com", got[0].Email)
	assert.Equal(t, "alice@example.com", got[1].Email)
}

func TestDedupeContributorsByEmail_SkipsEmptyEmail(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 1, 15, 8, 0, 0, 0, time.UTC)

	got := dedupeContributorsByEmail([]Contributor{
		{Email: "", LatestCommitDate: when},
		{Email: "dev@example.com", LatestCommitDate: when},
	})

	require.Len(t, got, 1)
	assert.Equal(t, "dev@example.com", got[0].Email)
}
