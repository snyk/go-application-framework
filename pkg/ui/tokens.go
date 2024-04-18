package ui

import "github.com/charmbracelet/lipgloss"

var tokenMap map[string]lipgloss.TerminalColor

func init() {
	tokenMap = map[string]lipgloss.TerminalColor{
		"severity.critical": lipgloss.AdaptiveColor{Light: "13", Dark: "5"},
		"severity.high":     lipgloss.AdaptiveColor{Light: "9", Dark: "1"},
		"severity.medium":   lipgloss.AdaptiveColor{Light: "9", Dark: "3"},
		"severity.low":      lipgloss.NoColor{},
		"text.plain":        lipgloss.NoColor{},
		"border.plain":      lipgloss.NoColor{},
	}
}

func TokenColor(name string) lipgloss.TerminalColor {
	val, ok := tokenMap[name]

	if !ok {
		return lipgloss.NoColor{}
	}

	return val
}
