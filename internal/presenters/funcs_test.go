package presenters

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(v int) *int {
	return &v
}

func TestResolveMessageArgs(t *testing.T) {
	testCases := []struct {
		desc string
		text string
		args []string
		want string
	}{
		{
			desc: "normal replacement of two placeholders",
			text: "input from {0} flows into {1}",
			args: []string{"a file", "readFile"},
			want: "input from a file flows into readFile",
		},
		{
			desc: "no placeholders in text",
			text: "no placeholders here",
			args: []string{"arg0"},
			want: "no placeholders here",
		},
		{
			desc: "empty args leaves placeholders intact",
			text: "{0} is {1}",
			args: []string{},
			want: "{0} is {1}",
		},
		{
			desc: "more placeholders than args leaves extras intact",
			text: "{0} and {1} and {2}",
			args: []string{"only", "two"},
			want: "only and two and {2}",
		},
		{
			desc: "empty text returns empty string",
			text: "",
			args: []string{"arg0"},
			want: "",
		},
		{
			desc: "nil args leaves placeholders intact",
			text: "text {0}",
			args: nil,
			want: "text {0}",
		},
		{
			desc: "single placeholder single arg",
			text: "hello {0}!",
			args: []string{"world"},
			want: "hello world!",
		},
		{
			desc: "repeated placeholder is replaced in all occurrences",
			text: "{0} and {0} again",
			args: []string{"val"},
			want: "val and val again",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := resolveMessageArgs(tc.text, tc.args)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReadLineMarked(t *testing.T) {
	// Create a temp file with known content for testing.
	tmpDir := t.TempDir()
	testFileName := "test_source.go"
	testFilePath := filepath.Join(tmpDir, testFileName)
	content := "hello world\n\tfmt.Println(x)\nabcdefghij\n"
	err := os.WriteFile(testFilePath, []byte(content), 0644)
	assert.NoError(t, err)

	cache := newSourceLineCache([]string{tmpDir})

	testCases := []struct {
		desc    string
		file    string
		line    int
		fromCol *int
		toCol   *int
		want    [3]string
	}{
		{
			desc:    "normal case - mark middle of line",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   intPtr(12),
			want:    [3]string{"hello ", "world", ""},
		},
		{
			desc:    "nil fromCol returns full line as prefix",
			file:    testFileName,
			line:    1,
			fromCol: nil,
			toCol:   intPtr(5),
			want:    [3]string{"hello world", "", ""},
		},
		{
			desc:    "nil toCol marks to end of line",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   nil,
			want:    [3]string{"hello ", "world", ""},
		},
		{
			desc:    "fromCol beyond line length returns full line as prefix with empty marker",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(100),
			toCol:   intPtr(105),
			want:    [3]string{"hello world", "", ""},
		},
		{
			desc:    "toCol before fromCol results in empty marker",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   intPtr(3),
			want:    [3]string{"hello ", "", "world"},
		},
		{
			desc:    "fromCol at 1 marks from beginning",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(1),
			toCol:   intPtr(6),
			want:    [3]string{"", "hello ", "world"},
		},
		{
			desc:    "missing file returns all empty strings",
			file:    "nonexistent.go",
			line:    1,
			fromCol: intPtr(1),
			toCol:   intPtr(5),
			want:    [3]string{"", "", ""},
		},
		{
			desc:    "line out of range returns all empty strings",
			file:    testFileName,
			line:    999,
			fromCol: intPtr(1),
			toCol:   intPtr(5),
			want:    [3]string{"", "", ""},
		},
		{
			desc:    "line 0 returns all empty strings",
			file:    testFileName,
			line:    0,
			fromCol: intPtr(1),
			toCol:   intPtr(5),
			want:    [3]string{"", "", ""},
		},
		{
			desc:    "second line with tab",
			file:    testFileName,
			line:    2,
			fromCol: intPtr(2),
			toCol:   intPtr(14),
			want:    [3]string{"\t", "fmt.Println(x", ")"},
		},
		{
			desc:    "mark entire line",
			file:    testFileName,
			line:    3,
			fromCol: intPtr(1),
			toCol:   nil,
			want:    [3]string{"", "abcdefghij", ""},
		},
		{
			desc:    "both fromCol and toCol nil returns full line as prefix",
			file:    testFileName,
			line:    1,
			fromCol: nil,
			toCol:   nil,
			want:    [3]string{"hello world", "", ""},
		},
		{
			desc:    "fromCol equals toCol gives single char marker due to 1-based fromCol",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(3),
			toCol:   intPtr(3),
			want:    [3]string{"he", "l", "lo world"},
		},
		{
			desc:    "toCol beyond line length is clamped",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   intPtr(100),
			want:    [3]string{"hello ", "world", ""},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := cache.ReadLineMarked(tc.file, tc.line, tc.fromCol, tc.toCol)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSourceLineCacheRejectsFilesOutsideBaseDirectory(t *testing.T) {
	parentDir := t.TempDir()
	baseDir := filepath.Join(parentDir, "project")
	require.NoError(t, os.Mkdir(baseDir, 0o755))

	outsideFile := filepath.Join(parentDir, "outside.go")
	require.NoError(t, os.WriteFile(outsideFile, []byte("secret\n"), 0o600))

	cache := newSourceLineCache([]string{baseDir})
	assert.Empty(t, cache.ReadLine(filepath.Join("..", "outside.go"), 1))
	assert.Empty(t, cache.ReadLine(outsideFile, 1))
}

func TestMarkdownToHTMLNormalizesLineEndings(t *testing.T) {
	rendered := string(MarkdownToHTML("line one\r\n```\nline two  \n   \n```\rline three"))

	assert.NotContains(t, rendered, "\r")
	assert.NotContains(t, rendered, "line two  \n")
	assert.NotContains(t, rendered, "\n   \n")
}
