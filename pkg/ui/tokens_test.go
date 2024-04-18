package ui_test

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/stretchr/testify/assert" // Using testify for better assertions
)

func TestTokenColorExistingToken(t *testing.T) {
	expectedColor := lipgloss.AdaptiveColor{Light: "13", Dark: "5"}
	actualColor := ui.TokenColor("severity.critical")
	assert.Equal(t, expectedColor, actualColor, "TokenColor should return the correct color for existing tokens")
}

func TestTokenColorNonexistentToken(t *testing.T) {
	expectedColor := lipgloss.NoColor{}
	actualColor := ui.TokenColor("invalid.token")
	assert.Equal(t, expectedColor, actualColor, "TokenColor should return NoColor for non-existent tokens")
}
