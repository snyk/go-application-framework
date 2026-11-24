package machineenrollment

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	frameworkModule = "github.com/snyk/go-application-framework"
	clientPackage   = frameworkModule + "/internal/machineenrollment"
)

func TestClientDoesNotImportTheFramework(t *testing.T) {
	var files []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".go" {
			files = append(files, path)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, files)
	require.Contains(t, files, filepath.Join("enrollmenttest", "enrollmenttest.go"))

	for _, file := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		require.NoError(t, err)

		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			require.NoError(t, err)
			if path == clientPackage || strings.HasPrefix(path, clientPackage+"/") {
				continue
			}
			assert.Falsef(t, path == frameworkModule || strings.HasPrefix(path, frameworkModule+"/"), "%s imports %s", file, path)
		}
	}
}
