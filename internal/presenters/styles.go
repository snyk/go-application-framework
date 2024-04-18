package presenters

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/ui"
)

var boxStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(ui.TokenColor("border.plain")).
	PaddingLeft(1).
	PaddingRight(4)

func renderBold(str string) string {
	return lipgloss.NewStyle().Bold(true).Render(str)
}

func renderInSeverityColor(severity string, str string) string {
	severityStyle := lipgloss.NewStyle().Foreground(
		ui.TokenColor("severity." + strings.ToLower(severity)),
	)
	return severityStyle.Render(str)
}
