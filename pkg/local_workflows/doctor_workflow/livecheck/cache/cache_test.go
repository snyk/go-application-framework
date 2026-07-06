package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func TestCheck_writableDir(t *testing.T) {
	dir := t.TempDir()

	ctx := mockCtx(t, dir)
	status := Check(ctx)

	assert.True(t, status.OK)
	assert.Equal(t, dir, status.Path)
	assert.Empty(t, status.ErrorMessage)

	// Probe file must be cleaned up.
	_, err := os.Stat(filepath.Join(dir, ".snyk-doctor-probe"))
	assert.True(t, os.IsNotExist(err))
}

func TestCheck_emptyPath(t *testing.T) {
	ctx := mockCtx(t, "")
	status := Check(ctx)

	assert.False(t, status.OK)
	assert.Equal(t, "cache path is not configured", status.ErrorMessage)
}

func TestCheck_nonexistentDir(t *testing.T) {
	ctx := mockCtx(t, filepath.Join(t.TempDir(), "does-not-exist"))
	status := Check(ctx)

	assert.False(t, status.OK)
	assert.Contains(t, status.ErrorMessage, "does not exist")
}

func TestCheck_notADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "regular-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	ctx := mockCtx(t, file)
	status := Check(ctx)

	assert.False(t, status.OK)
	assert.Contains(t, status.ErrorMessage, "not a directory")
}

func TestCheck_readOnlyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "readonly")
	require.NoError(t, os.Mkdir(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	ctx := mockCtx(t, dir)
	status := Check(ctx)

	assert.False(t, status.OK)
	assert.Contains(t, status.ErrorMessage, "not writable")
}

func TestCacheStatus_findings(t *testing.T) {
	ok := CacheStatus{OK: true, Path: "/tmp/cache"}.Findings()
	require.Len(t, ok, 1)
	assert.Equal(t, diagnosis.ProducerEnvironment, ok[0].Producer)
	assert.Equal(t, diagnosis.KindCacheOK, ok[0].Kind)
	assert.Equal(t, diagnosis.SeverityInfo, ok[0].Severity)
	assert.Equal(t, "/tmp/cache", ok[0].Fields["path"])

	failed := CacheStatus{ErrorMessage: "not writable", Path: "/tmp/cache"}.Findings()
	require.Len(t, failed, 1)
	assert.Equal(t, diagnosis.ProducerEnvironment, failed[0].Producer)
	assert.Equal(t, diagnosis.KindCacheFailure, failed[0].Kind)
	assert.Equal(t, diagnosis.SeverityWarning, failed[0].Severity)
}

func mockCtx(t *testing.T, cachePath string) *mocks.MockInvocationContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	config := configuration.NewWithOpts()
	if cachePath != "" {
		config.Set(configuration.CACHE_PATH, cachePath)
	}

	ctx := mocks.NewMockInvocationContext(ctrl)
	ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	return ctx
}
