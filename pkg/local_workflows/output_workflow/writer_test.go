package output_workflow

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// stubOutputDestination is a minimal iUtils.OutputDestination for tests in
// this package; stdout-style output goes to an in-memory buffer while file
// operations hit the real filesystem (callers should use t.TempDir() paths).
type stubOutputDestination struct {
	buffer bytes.Buffer
}

func (s *stubOutputDestination) Println(a ...any) (n int, err error) {
	return fmt.Fprintln(&s.buffer, a...)
}

func (s *stubOutputDestination) Remove(name string) error {
	return os.Remove(name)
}

func (s *stubOutputDestination) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

func (s *stubOutputDestination) GetWriter() io.Writer {
	return &s.buffer
}

func Test_GetWritersFromConfiguration_HTMLFileWriter(t *testing.T) {
	t.Run("html-file-output set creates an HTML file writer", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(OUTPUT_CONFIG_KEY_HTML_FILE, "/tmp/x.html")

		writerMap := GetWritersFromConfiguration(config, &stubOutputDestination{})

		htmlWriters := writerMap.PopWritersByMimetype(HTML_MIME_TYPE)
		assert.Len(t, htmlWriters, 1)
		assert.Equal(t, HTML_MIME_TYPE, htmlWriters[0].mimeType)
		assert.Equal(t, OUTPUT_CONFIG_KEY_HTML_FILE, htmlWriters[0].name)
	})

	t.Run("html-file-output unset creates no HTML writer", func(t *testing.T) {
		config := configuration.NewWithOpts()

		writerMap := GetWritersFromConfiguration(config, &stubOutputDestination{})

		htmlWriters := writerMap.PopWritersByMimetype(HTML_MIME_TYPE)
		assert.Empty(t, htmlWriters)
	})
}

func Test_getDefaultWriterMimeType(t *testing.T) {
	testCases := []struct {
		name             string
		configKeys       []string
		expectedMimeType string
	}{
		{
			name:             "no flags set returns default",
			configKeys:       nil,
			expectedMimeType: DEFAULT_MIME_TYPE,
		},
		{
			name:             "sarif",
			configKeys:       []string{OUTPUT_CONFIG_KEY_SARIF},
			expectedMimeType: SARIF_MIME_TYPE,
		},
		{
			name:             "json",
			configKeys:       []string{OUTPUT_CONFIG_KEY_JSON},
			expectedMimeType: JSON_MIME_TYPE,
		},
		{
			name:             "html",
			configKeys:       []string{OUTPUT_CONFIG_KEY_HTML},
			expectedMimeType: HTML_MIME_TYPE,
		},
		{
			name:             "sarif takes precedence over html",
			configKeys:       []string{OUTPUT_CONFIG_KEY_SARIF, OUTPUT_CONFIG_KEY_HTML},
			expectedMimeType: SARIF_MIME_TYPE,
		},
		{
			name:             "json takes precedence over html",
			configKeys:       []string{OUTPUT_CONFIG_KEY_JSON, OUTPUT_CONFIG_KEY_HTML},
			expectedMimeType: JSON_MIME_TYPE,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			for _, key := range tc.configKeys {
				config.Set(key, true)
			}

			assert.Equal(t, tc.expectedMimeType, getDefaultWriterMimeType(config))
		})
	}
}
