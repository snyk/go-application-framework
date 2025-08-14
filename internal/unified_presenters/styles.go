package unified_presenters

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var boxStyle = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.NoColor{}).
	PaddingLeft(1).
	PaddingRight(4)

// renderBold renders text in bold style.
func renderBold(str string) string {
	return lipgloss.NewStyle().Bold(true).Render(str)
}

// renderSeverityColor returns the color code for a given severity level.
func renderSeverityColor(severity string) string {
	upperSeverity := strings.ToUpper(severity)
	var style lipgloss.TerminalColor
	switch {
	case strings.Contains(upperSeverity, "CRITICAL"):
		// Purple
		style = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}
	case strings.Contains(upperSeverity, "HIGH"):
		// Red
		style = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	case strings.Contains(upperSeverity, "MEDIUM"):
		// Yellow/Orange
		style = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	default:
		style = lipgloss.NoColor{}
	}
	severityStyle := lipgloss.NewStyle().Foreground(style)
	return severityStyle.Render(severity)
}

// renderGreen renders text in green.
func renderGreen(str string) string {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	return style.Render(str)
}
