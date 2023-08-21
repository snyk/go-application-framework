package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultBuilder_NoError(t *testing.T) {
	ui, err := NewConsoleUiBuilder().Build()
	assert.NotNil(t, ui)
	assert.NoError(t, err)
}
