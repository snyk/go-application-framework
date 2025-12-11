package fileupload

import (
	"golang.org/x/net/context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ListsSources_Simplest(t *testing.T) {
	sourcesDir := filepath.Join("testdata", "simplest")

	files, err := walkDirForPath(sourcesDir)
	require.NoError(t, err)
	assert.Len(t, files, 2, "Expecting 2 files")
	assert.Contains(t, files, filepath.Join(sourcesDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "src", "index.js"))
}

func Test_ListsSources_WithIgnores(t *testing.T) {
	sourcesDir := filepath.Join("testdata", "with-ignores")

	files, err := walkDirForPath(sourcesDir)
	require.NoError(t, err)

	assert.Len(t, files, 3, "Expecting 3 files")
	assert.Contains(t, files, filepath.Join(sourcesDir, ".gitignore"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "src", "with-ignores.js"))
}

func walkDirForPath(sourcesDir string) ([]string, error) {
	filesCh := make(chan string, 10)
	errCh := make(chan error, 1)

	go func() {
		defer close(filesCh)
		errCh <- listSources(context.TODO(), sourcesDir, filesCh)
	}()

	files := []string{}
	for {
		select {
		case file, ok := <-filesCh:
			if !ok {
				return files, nil
			}
			files = append(files, file)
		case err := <-errCh:
			if err != nil {
				return nil, err
			}
		}
	}
}
