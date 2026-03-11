package uploadrevision

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrlfNormReader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"CRLF to LF", "line1\r\nline2\r\nline3\r\n", "line1\nline2\nline3\n"},
		{"LF unchanged", "line1\nline2\n", "line1\nline2\n"},
		{"lone CR preserved", "a\rb\rc", "a\rb\rc"},
		{"mixed line endings", "a\r\nb\nc\r\nd\re", "a\nb\nc\nd\re"},
		{"empty input", "", ""},
		{"no line endings", "hello world", "hello world"},
		{"only CRLF", "\r\n", "\n"},
		{"consecutive CRLF", "\r\n\r\n\r\n", "\n\n\n"},
		{"CRLF at start", "\r\nfoo", "\nfoo"},
		{"trailing CR at end", "foo\r", "foo\r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &crlfNormReader{r: strings.NewReader(tt.input)}
			got, err := io.ReadAll(reader)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
