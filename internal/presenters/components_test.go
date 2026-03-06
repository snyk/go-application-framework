package presenters

import (
	"context"
	"fmt"
	"github.com/snyk/go-application-framework/pkg/networking"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/stretchr/testify/assert"
)

func Test_RenderError(t *testing.T) {
	defaultContext := context.Background()
	contextWithInteractionId := context.WithValue(defaultContext, networking.InteractionIdKey, "urn:snyk:interaction:some-UUID")

	for _, severity := range []string{"warn", "error", "fatal"} {
		t.Run(
			fmt.Sprintf("colors for severity %s", severity), func(t *testing.T) {
				err := snyk.NewTooManyRequestsError("")
				err.Level = severity
				lipgloss.SetColorProfile(termenv.TrueColor)
				output := RenderError(err, defaultContext)
				snaps.MatchSnapshot(t, output)

				lipgloss.SetColorProfile(termenv.TrueColor)
				lipgloss.SetHasDarkBackground(true)
				outputDark := RenderError(err, defaultContext)
				snaps.MatchSnapshot(t, outputDark)
			})
	}

	t.Run("without status code", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("A short error description")
		// no error code => no error catalog link
		err.StatusCode = 0
		output := RenderError(err, defaultContext)

		assert.NotContains(t, output, "Status:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("without links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("A short error description")
		// no error code => no error catalog link
		err.ErrorCode = ""
		output := RenderError(err, defaultContext)

		assert.NotContains(t, output, "Help:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewServerError("An error")
		err.Links = append(err.Links, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code")
		output := RenderError(err, defaultContext)

		assert.Contains(t, output, "Docs:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with context", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewServerError("An error")
		err.Links = append(err.Links, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code")
		output := RenderError(err, contextWithInteractionId)

		assert.Contains(t, output, "Docs:")
		assert.Contains(t, output, "ID:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("detail with URL should not break URL", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("Error description")
		err.Detail = "For more information see https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code-with-a-very-long-url-that-would-normally-wrap"
		output := RenderError(err, defaultContext)

		// URL should be on a single line without breaking
		assert.Contains(t, output, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code-with-a-very-long-url-that-would-normally-wrap")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("detail without URL should apply width constraint", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("Error description")
		err.Detail = "This is a long detail message without any URLs that should be wrapped according to the normal width constraints for better readability in the terminal"
		output := RenderError(err, defaultContext)

		snaps.MatchSnapshot(t, output)
	})
}

func Test_containsURL(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected bool
	}{
		{
			name:     "contains http URL",
			text:     "Visit http://example.com for more info",
			expected: true,
		},
		{
			name:     "contains https URL",
			text:     "See https://docs.snyk.io/some/path for details",
			expected: true,
		},
		{
			name:     "no URL",
			text:     "This is just plain text without any links",
			expected: false,
		},
		{
			name:     "URL with query parameters",
			text:     "Check https://example.com?param=value&other=123",
			expected: true,
		},
		{
			name:     "URL with fragment",
			text:     "See https://example.com/path#section",
			expected: true,
		},
		{
			name:     "empty string",
			text:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsURL(tt.text)
			assert.Equal(t, tt.expected, result)
		})
	}
}
