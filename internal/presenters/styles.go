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
		"LOW":      lipgloss.NoColor{},
		"MEDIUM":   lipgloss.AdaptiveColor{Light: "11", Dark: "3"},
		"HIGH":     lipgloss.AdaptiveColor{Light: "9", Dark: "1"},
		"CRITICAL": lipgloss.AdaptiveColor{Light: "13", Dark: "5"},
	}
	severityStyle := lipgloss.NewStyle().Foreground(severityToColor[strings.ToUpper(severity)])
	return severityStyle.Render(str)
}

func renderGreen(str string) string {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	return style.Render(str)
}

func renderGray(str string) string {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	return style.Render(str)
}
