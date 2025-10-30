package listsources_test

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	listsources "github.com/snyk/go-application-framework/pkg/apiclients/fileupload/files"
)

func Test_ListsSources_Simplest(t *testing.T) {
	sourcesDir := filepath.Join("testdata", "simplest")

	files, err := listSourcesForPath(sourcesDir)
	require.NoError(t, err)
	assert.Len(t, files, 2, "Expecting 2 files")
	assert.Contains(t, files, filepath.Join(sourcesDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "src", "index.js"))
}

func Test_ListsSources_WithIgnores(t *testing.T) {
	sourcesDir := filepath.Join("testdata", "with-ignores")

	files, err := listSourcesForPath(sourcesDir)
	require.NoError(t, err)

	assert.Len(t, files, 3, "Expecting 3 files")
	assert.Contains(t, files, filepath.Join(sourcesDir, ".gitignore"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "src", "with-ignores.js"))
}

func listSourcesForPath(sourcesDir string) ([]string, error) {
	mockLogger := zerolog.New(io.Discard)
	filesCh, err := listsources.ForPath(sourcesDir, &mockLogger, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources: %w", err)
	}

	files := []string{}
	for file := range filesCh {
		files = append(files, file)
	}

	return files, nil
}
