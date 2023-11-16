package runtimeinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuntimeInfo_New(t *testing.T) {
	ri := New()

	assert.NotNil(t, ri)
}

func TestRuntimeInfo_NewWithName(t *testing.T) {
	ri := New(WithName("asdf"))

	assert.Equal(t, "asdf", ri.GetName())
}

func TestRuntimeInfo_NewWithVersion(t *testing.T) {
	ri := New(WithVersion("1.2.3"))

	assert.Equal(t, "1.2.3", ri.GetVersion())
}
