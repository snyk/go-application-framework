package fileupload

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_updateCommonRoot(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  string
	}{
		{
			name: "Single file returns its directory",
			files: []string{
				filepath.Join("users", "alice", "doc.txt"),
			},
			want: filepath.Join("users", "alice"),
		},
		{
			name: "Siblings in same folder",
			files: []string{
				filepath.Join("src", "main.go"),
				filepath.Join("src", "utils.go"),
			},
			want: filepath.Join("src"),
		},
		{
			name: "Nested mix (parent and child)",
			files: []string{
				filepath.Join("project", "README.md"),
				filepath.Join("project", "src", "app.go"),
			},
			want: filepath.Join("project"),
		},
		{
			name: "Siblings in different subdirectories",
			files: []string{
				filepath.Join("app", "backend", "server.go"),
				filepath.Join("app", "frontend", "ui.js"),
			},
			want: filepath.Join("app"),
		},
		{
			name: "Deep nesting divergence",
			files: []string{
				filepath.Join("a", "b", "c", "d", "file1.txt"),
				filepath.Join("a", "b", "c", "x", "file2.txt"),
			},
			want: filepath.Join("a", "b", "c"),
		},
		{
			name: "Root divergence (completely different paths)",
			files: []string{
				filepath.Join("var", "log", "syslog"),
				filepath.Join("home", "user", "file.txt"),
			},
			// Rel fails or returns ".." prefix -> falls back to "."
			want: ".",
		},
		{
			name: "Accordion Effect (Deep -> Shallow -> Deep)",
			files: []string{
				filepath.Join("a", "b", "c", "d", "1.txt"), // Root: a/b/c/d
				filepath.Join("a", "b", "x", "2.txt"),      // Root becomes: a/b
				filepath.Join("a", "b", "c", "3.txt"),      // Root stays: a/b
			},
			want: filepath.Join("a", "b"),
		},
		{
			name: "Absolute paths divergence (simulated)",
			files: []string{
				"/var/www/html/index.html",
				"/var/log/nginx/access.log",
			},
			want: filepath.FromSlash("/var"),
		},
		{
			name: "Mixed depth at root",
			files: []string{
				filepath.FromSlash("/a.txt"),
				filepath.FromSlash("/var/b.txt"),
			},
			want: filepath.FromSlash("/"),
		},
		{
			name: "Explicit relative dot paths",
			files: []string{
				"./a/b/file.txt",
				"a/c/file.txt",
			},
			// filepath.Dir cleans "./a/b" to "a/b"
			// So common root between "a/b" and "a/c" is "a"
			want: "a",
		},
		{
			name: "Ascending relative paths (Parent references)",
			files: []string{
				filepath.Join("..", "src", "main.go"),
				filepath.Join("..", "test", "main_test.go"),
			},
			// Both start with "..", so that is their common root
			want: "..",
		},
		{
			name: "Path cleaning (redundant slashes and dots)",
			files: []string{
				"src//utils/./math.go",       // Normalizes to src/utils/math.go
				"src/utils/../utils/sort.go", // Normalizes to src/utils/sort.go
			},
			want: filepath.Join("src", "utils"),
		},
		{
			name: "Parent directory references",
			files: []string{
				"../app/main.go",
				"../app/config.json",
			},
			// Both live in ../app
			want: filepath.Join("..", "app"),
		},
		{
			name: "Monorepo: Distinct Services",
			files: []string{
				"services/auth/main.go",
				"services/billing/api.go",
				"services/frontend/index.ts",
			},
			// They all share the "services" folder
			want: "services",
		},
		{
			name: "Small Project",
			files: []string{
				"go.mod",
				"cmd/main.go",
				"pkg/utils/str.go",
			},
			// The lowest common ancestor is the current directory (".")
			// because "go.mod" sits at the top.
			want: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commonRoot string
			for _, file := range tt.files {
				commonRoot = updateCommonRoot(commonRoot, file)
			}

			assert.Equal(t, tt.want, commonRoot)
		})
	}
}
