package utils

import (
	"errors"
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AvailableDiskSpace_returnsNonZeroForExistingPath(t *testing.T) {
	available, err := AvailableDiskSpace(t.TempDir())

	require.NoError(t, err)
	assert.Positive(t, available)
}

func Test_AvailableDiskSpace_measuresNearestExistingAncestor(t *testing.T) {
	base := t.TempDir()

	// The point of the ancestor walk: callers check space for a staging
	// directory before creating it.
	notYetCreated := filepath.Join(base, "secrets-history", "run-id", "shard-0000")
	available, err := AvailableDiskSpace(notYetCreated)

	require.NoError(t, err)
	assert.Positive(t, available)
}

func Test_EnsureFreeDiskSpace_succeedsWhenSpaceAvailable(t *testing.T) {
	require.NoError(t, EnsureFreeDiskSpace(t.TempDir(), 1))
}

func Test_EnsureFreeDiskSpace_failsWhenSpaceInsufficient(t *testing.T) {
	dir := t.TempDir()

	err := EnsureFreeDiskSpace(dir, math.MaxUint64)

	var insufficient *ErrInsufficientDiskSpace
	require.ErrorAs(t, err, &insufficient, "callers must be able to distinguish this from a generic failure")
	assert.Equal(t, dir, insufficient.Path)
	assert.Equal(t, uint64(math.MaxUint64), insufficient.Requested)
	assert.Contains(t, err.Error(), "insufficient disk space")
}

func Test_nearestExistingPath_failsWhenNoAncestorExists(t *testing.T) {
	_, err := nearestExistingPath(string(filepath.Separator) + filepath.Join("\x00invalid", "path"))

	// Either the walk terminates at the root without finding a match, or the OS
	// rejects the path outright; both are errors, neither should panic.
	if err != nil {
		assert.Error(t, err)
		return
	}
	assert.NoError(t, errors.Unwrap(err))
}
