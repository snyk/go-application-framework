package local_models

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
)

func TestTemplateGitContextLogic(t *testing.T) {
	// Template logic similar to what's in local_finding.tmpl
	templateStr := `{{- if and (eq .Summary.Type "sast") .Links.report (or (not .GitContext) (eq .GitContext.RepositoryUrl "")) }}
Warning: Some capabilities are unavailable.
{{- end }}`

	tmpl, err := template.New("test").Parse(templateStr)
	assert.NoError(t, err)

	tests := []struct {
		name           string
		localFinding   LocalFinding
		expectWarning  bool
		description    string
	}{
		{
			name: "No git context - should show warning",
			localFinding: LocalFinding{
				Summary: TypesFindingsSummary{Type: "sast"},
				Links:   map[string]string{"report": "http://example.com"},
				GitContext: nil,
			},
			expectWarning: true,
			description: "When GitContext is nil, warning should be shown",
		},
		{
			name: "Empty repository URL - should show warning",
			localFinding: LocalFinding{
				Summary: TypesFindingsSummary{Type: "sast"},
				Links:   map[string]string{"report": "http://example.com"},
				GitContext: &GitContext{
					RepositoryUrl: "",
					Branch:        "main",
				},
			},
			expectWarning: true,
			description: "When repository URL is empty, warning should be shown",
		},
		{
			name: "Valid git context - should not show warning",
			localFinding: LocalFinding{
				Summary: TypesFindingsSummary{Type: "sast"},
				Links:   map[string]string{"report": "http://example.com"},
				GitContext: &GitContext{
					RepositoryUrl: "https://github.com/example/repo.git",
					Branch:        "main",
				},
			},
			expectWarning: false,
			description: "When git context is valid, warning should not be shown",
		},
		{
			name: "Non-SAST scan - should not show warning",
			localFinding: LocalFinding{
				Summary: TypesFindingsSummary{Type: "sca"},
				Links:   map[string]string{"report": "http://example.com"},
				GitContext: nil,
			},
			expectWarning: false,
			description: "When scan type is not SAST, warning should not be shown",
		},
		{
			name: "No report link - should not show warning",
			localFinding: LocalFinding{
				Summary: TypesFindingsSummary{Type: "sast"},
				Links:   map[string]string{},
				GitContext: nil,
			},
			expectWarning: false,
			description: "When there's no report link, warning should not be shown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tmpl.Execute(&buf, tt.localFinding)
			assert.NoError(t, err)

			output := buf.String()
			hasWarning := strings.Contains(output, "Warning: Some capabilities are unavailable.")

			assert.Equal(t, tt.expectWarning, hasWarning, tt.description)
		})
	}
}
