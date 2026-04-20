package presenters_test

import (
	"bytes"
	"os"
	"regexp"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
)

func normalizeHTMLTime(s string) string {
	s = regexp.MustCompile(`<p class="timestamp">[^<]*</p>`).ReplaceAllString(s, `<p class="timestamp"><TIME></p>`)
	return s
}

func TestHTMLReportRenderer_CodeNoIssues(t *testing.T) {
	data, err := os.ReadFile("testdata/no-issues.json")
	require.NoError(t, err)

	h, err := presenters.NewHTMLReportRenderer(presenters.HTMLReportKindCode)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, h.Render(&buf, data))

	html := buf.String()
	assert.Contains(t, html, "Snyk Code Report")
	assert.Contains(t, html, "No issues found")
	snaps.MatchSnapshot(t, normalizeHTMLTime(html))
}

func TestHTMLReportRenderer_SCA_noVulns(t *testing.T) {
	data, err := os.ReadFile("testdata/html-sca-no-vulns.json")
	require.NoError(t, err)

	h, err := presenters.NewHTMLReportRenderer(presenters.HTMLReportKindSCA)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, h.Render(&buf, data))

	html := buf.String()
	assert.Contains(t, html, "No known vulnerabilities detected.")
	assert.Contains(t, html, "test-proj")
	snaps.MatchSnapshot(t, normalizeHTMLTime(html))
}

func TestHTMLReportRenderer_CustomTemplateMissingFile(t *testing.T) {
	_, err := presenters.NewHTMLReportRenderer(
		presenters.HTMLReportKindCode,
		presenters.WithHTMLReportCustomTemplate("/nonexistent/template.hbs"),
	)
	require.Error(t, err)
}
