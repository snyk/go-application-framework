//go:build unix

package fileupload_test

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
)

func TestLargeFileUpload_NamedPipe(t *testing.T) {
	t.Run("named pipe is skipped without blocking on open", func(t *testing.T) {
		client, _, path := setupLargeFileTest(t, []byte("x"))
		fifo := filepath.Join(filepath.Dir(path), "pipe")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))

		type result struct {
			res fileupload.UploadResult
			err error
		}
		done := make(chan result, 1)
		go func() {
			res, err := createFromLargeFile(t.Context(), client, fifo)
			done <- result{res, err}
		}()

		select {
		case r := <-done:
			require.ErrorIs(t, r.err, fileupload.ErrNoFilesProvided)
			require.Len(t, r.res.SkippedFiles, 1)
			var specialErr *fileupload.SpecialFileError
			require.ErrorAs(t, r.res.SkippedFiles[0].Reason, &specialErr)
			assert.Equal(t, "pipe", r.res.SkippedFiles[0].Path)
		case <-time.After(5 * time.Second):
			// Unblock the stuck open so the goroutine does not outlive the test.
			unblockFifo(fifo)
			t.Fatal("upload blocked on a named pipe")
		}
	})
}

// unblockFifo opens the pipe for writing without blocking, which releases a reader stuck in open.
func unblockFifo(path string) {
	if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		_ = syscall.Close(fd)
	}
}
