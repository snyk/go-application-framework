package presenters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOONTemplate_nestedGoldens(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"mixed", "nested"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join("testdata", "ufm", "toon", name)
			input, err := os.ReadFile(path + ".json")
			require.NoError(t, err)
			expected, err := os.ReadFile(path + ".toon")
			require.NoError(t, err)
			assert.Equal(t, strings.TrimSuffix(string(expected), "\n"), renderTOONValue(t, string(input)))
		})
	}
}

func TestTOONTemplate_genericValues(t *testing.T) {
	t.Parallel()
	output := renderTOONValue(t, `{
		"arrays":[[],[[true,false],null]],
		"credits":["Doe, Jane","Smith"],
		"nestedCredits":[["Doe, Jane","Smith"]],
		"numbers":[9007199254740993,-9007199254740993,0.1234567890123456789],
		"rows":[{"a":[1,2]},{"a":[{"nested":{"value":true}}]}]
	}`)
	assert.Contains(t, output, "numbers[3]: 9007199254740993,-9007199254740993,0.1234567890123456789")
	assert.Contains(t, output, `credits[2]: "Doe, Jane",Smith`)
	assert.Contains(t, output, "nestedCredits[1]:\n  - [2]: \"Doe, Jane\",Smith")
	assert.Contains(t, output, "arrays[2]:\n  - []\n  - [2]:\n    - [2]: true,false\n    - null")
	assert.Contains(t, output, "rows[2]:\n  - a[2]: 1,2\n  - a[1]{nested{value}}:\n      true")
}

func renderTOONValue(t *testing.T, input string) string {
	t.Helper()
	var value any
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&value))
	functions := getToonTemplateFuncMap()
	functions["getContext"] = t.Context
	tmpl := template.New("toon").Funcs(getDefaultTemplateFuncMap(configuration.NewWithOpts(), nil)).Funcs(functions)
	require.NoError(t, loadTemplates(ApplicationTOONTemplatesUfm, tmpl))
	var output bytes.Buffer
	require.NoError(t, tmpl.ExecuteTemplate(&output, "toonDocument", value))
	return output.String()
}
