//go:build unix

package configuration

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WithPinnedFile_NamedPipeIsRejectedInsteadOfBlocking(t *testing.T) {
	isolateHome(t)
	pipe := filepath.Join(t.TempDir(), "pipe")
	require.NoError(t, syscall.Mkfifo(pipe, 0o600))
	logs := captureLog(t)

	done := make(chan Configuration, 1)
	go func() { done <- NewWithOpts(WithPinnedFile(pipe)) }()
	select {
	case c := <-done:
		assert.Nil(t, c.GetStorage())
		assert.Contains(t, logs.String(), "not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("NewWithOpts blocked on a named pipe")
	}
}
