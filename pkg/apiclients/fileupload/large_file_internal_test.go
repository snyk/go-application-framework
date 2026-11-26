package fileupload

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func identity(p string) string { return p }

func Test_planChunks_ChunkSizeBounds(t *testing.T) {
	t.Run("chunk size below the minimum is rejected", func(t *testing.T) {
		_, err := planChunks("bundle", 1_000_000, minChunkSize-1, 256, identity)
		var sizeErr *InvalidChunkSizeError
		require.ErrorAs(t, err, &sizeErr)
		assert.Equal(t, minChunkSize-1, sizeErr.ChunkSize)
		assert.Equal(t, minChunkSize, sizeErr.MinSize)
	})

	t.Run("minimum chunk size is accepted", func(t *testing.T) {
		chunks, err := planChunks("bundle", 2*minChunkSize, minChunkSize, 256, identity)
		require.NoError(t, err)
		assert.Len(t, chunks, 2)
	})

	t.Run("maximum number of chunks is accepted", func(t *testing.T) {
		chunks, err := planChunks("bundle", maxChunkCount*minChunkSize, minChunkSize, 256, identity)
		require.NoError(t, err)
		require.Len(t, chunks, int(maxChunkCount))
		assert.Equal(t, "bundle_chunk_v1_9999", chunks[len(chunks)-1].name)
	})

	t.Run("more chunks than the 4 digit chunk number allows is rejected", func(t *testing.T) {
		_, err := planChunks("bundle", maxChunkCount*minChunkSize+1, minChunkSize, 256, identity)
		var countErr *ChunkCountLimitError
		require.ErrorAs(t, err, &countErr)
		assert.Equal(t, "bundle", countErr.FilePath)
		assert.Equal(t, maxChunkCount+1, countErr.ChunkCount)
		assert.Equal(t, maxChunkCount, countErr.Limit)
	})
}

func Test_openLargeFile_SizeLimit(t *testing.T) {
	write := func(t *testing.T, size int) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bundle")
		require.NoError(t, os.WriteFile(path, make([]byte, size), 0o600))
		return path
	}

	t.Run("file of exactly the limit is accepted", func(t *testing.T) {
		file, size, err := openLargeFile(write(t, 100), "bundle", 100)
		require.NoError(t, err)
		require.NoError(t, file.Close())
		assert.EqualValues(t, 100, size)
	})

	t.Run("file over the limit is rejected", func(t *testing.T) {
		file, _, err := openLargeFile(write(t, 101), "bundle", 100)
		require.Nil(t, file)
		var sizeErr *FileSizeLimitError
		require.ErrorAs(t, err, &sizeErr)
		assert.Equal(t, "bundle", sizeErr.FilePath)
	})
}

func Test_planChunks_NameLengthLimit(t *testing.T) {
	const path = "src/bundle"
	nameLength := len(fmt.Sprintf(chunkNameFormat, path, version, int64(0)))

	t.Run("name of exactly the limit is accepted", func(t *testing.T) {
		chunks, err := planChunks(path, 1, minChunkSize, nameLength, identity)
		require.NoError(t, err)
		assert.Len(t, chunks, 1)
	})

	t.Run("name one over the limit is rejected before any upload", func(t *testing.T) {
		_, err := planChunks(path, 1, minChunkSize, nameLength-1, identity)
		var limitErr *FilePathLengthLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Equal(t, nameLength, limitErr.Length)
		assert.Equal(t, nameLength-1, limitErr.Limit)
	})

	t.Run("the limit applies to the encoded name", func(t *testing.T) {
		encode := func(p string) string { return strings.ReplaceAll(p, "/", "%2F") }

		_, err := planChunks(path, 1, minChunkSize, nameLength, encode)
		var limitErr *FilePathLengthLimitError
		require.ErrorAs(t, err, &limitErr)
		assert.Contains(t, limitErr.FilePath, "src%2Fbundle")
	})
}

func Test_chunkReader_DetectsTruncation(t *testing.T) {
	content := []byte("0123456789")
	file := func(t *testing.T, data []byte) *os.File {
		t.Helper()
		f, err := os.Create(filepath.Join(t.TempDir(), "bundle"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })
		_, err = f.Write(data)
		require.NoError(t, err)
		return f
	}

	t.Run("complete chunk is read", func(t *testing.T) {
		got, err := io.ReadAll(newChunkReader(file(t, content), chunk{name: "c", offset: 4, length: 6}))
		require.NoError(t, err)
		assert.Equal(t, "456789", string(got))
	})

	t.Run("file truncated inside the chunk is an error", func(t *testing.T) {
		got, err := io.ReadAll(newChunkReader(file(t, content[:7]), chunk{name: "c", offset: 4, length: 6}))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.Equal(t, "456", string(got))
	})

	t.Run("file truncated before the chunk is an error", func(t *testing.T) {
		_, err := io.ReadAll(newChunkReader(file(t, content[:2]), chunk{name: "c", offset: 4, length: 6}))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("empty chunk of an empty file is read", func(t *testing.T) {
		got, err := io.ReadAll(newChunkReader(file(t, nil), chunk{name: "c"}))
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}
