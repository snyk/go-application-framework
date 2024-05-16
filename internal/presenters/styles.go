package presenters

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var boxStyle = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.NoColor{}).
	PaddingLeft(1).
	PaddingRight(4)

func renderBold(str string) string {
	return lipgloss.NewStyle().Bold(true).Render(str)
}

func renderInSeverityColor(severity string, str string) string {
	severityToColor := map[string]lipgloss.TerminalColor{
		"LOW":    lipgloss.NoColor{},
		"MEDIUM": lipgloss.AdaptiveColor{Light: "11", Dark: "3"},
		"HIGH":   lipgloss.AdaptiveColor{Light: "9", Dark: "1"},
	}
	severityStyle := lipgloss.NewStyle().Foreground(severityToColor[strings.ToUpper(severity)])
	return severityStyle.Render(str)
}
