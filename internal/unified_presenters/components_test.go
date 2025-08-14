package unified_presenters_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

func Test_RenderError(t *testing.T) {
	defaultContext := context.Background()
	contextWithInteractionID := context.WithValue(defaultContext, networking.InteractionIdKey, "urn:snyk:interaction:some-UUID")

	for _, severity := range []string{"warn", "error", "fatal"} {
		t.Run(
			fmt.Sprintf("colors for severity %s", severity), func(t *testing.T) {
				err := snyk.NewTooManyRequestsError("")
				err.Level = severity
				lipgloss.SetColorProfile(termenv.TrueColor)
				output := presenters.RenderError(defaultContext, &err)
				snaps.MatchSnapshot(t, output)

				lipgloss.SetColorProfile(termenv.TrueColor)
				lipgloss.SetHasDarkBackground(true)
				outputDark := presenters.RenderError(defaultContext, &err)
				snaps.MatchSnapshot(t, outputDark)
			})
	}

	t.Run("without status code", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("A short error description")
		// no error code => no error catalog link
		err.StatusCode = 0
		output := presenters.RenderError(defaultContext, &err)

		assert.NotContains(t, output, "Status:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("without links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("A short error description")
		// no error code => no error catalog link
		err.ErrorCode = ""
		output := presenters.RenderError(defaultContext, &err)

		assert.NotContains(t, output, "Help:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewServerError("An error")
		err.Links = append(err.Links, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code")
		output := presenters.RenderError(defaultContext, &err)

		assert.Contains(t, output, "Docs:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with context", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewServerError("An error")
		err.Links = append(err.Links, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code")
		output := presenters.RenderError(contextWithInteractionID, &err)

		assert.Contains(t, output, "Docs:")
		assert.Contains(t, output, "ID:")
		snaps.MatchSnapshot(t, output)
	})
}
