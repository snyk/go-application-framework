package presenters

import (
	"fmt"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/stretchr/testify/assert"
)

func Test_RenderError(t *testing.T) {
	for _, severity := range []string{"warn", "error", "fatal"} {
		t.Run(
			fmt.Sprintf("colors for severity %s", severity), func(t *testing.T) {
				err := snyk.NewTooManyRequestsError("")
				err.Level = severity
				lipgloss.SetColorProfile(termenv.TrueColor)
				output := RenderError(err)
				snaps.MatchSnapshot(t, output)

				lipgloss.SetColorProfile(termenv.TrueColor)
				lipgloss.SetHasDarkBackground(true)
				outputDark := RenderError(err)
				snaps.MatchSnapshot(t, outputDark)
			})
	}

	t.Run("without links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		output := RenderError(snyk.NewBadRequestError("A short error description"))

		assert.NotContains(t, output, "Help:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		output := RenderError(snyk.NewServerError("An error"))

		assert.Contains(t, output, "Help:")
		snaps.MatchSnapshot(t, output)
	})
}
