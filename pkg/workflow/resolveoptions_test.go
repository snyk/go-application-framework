package workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestResolveInvokeOptions_ReturnsInputAndConfig(t *testing.T) {
	base := configuration.New()
	id := NewTypeIdentifier(NewWorkflowIdentifier("sibling"), "data")
	input := []Data{NewData(id, "text/plain", []byte("payload"))}

	override := configuration.New()
	override.Set("k", "v")

	cfg, gotInput := ResolveInvokeOptions(base, WithInput(input), WithConfig(override))

	require.Len(t, gotInput, 1)
	assert.Equal(t, []byte("payload"), gotInput[0].GetPayload())
	assert.Equal(t, "v", cfg.GetString("k"), "WithConfig override should win")
}

func TestResolveInvokeOptions_DefaultsToBaseAndEmptyInput(t *testing.T) {
	base := configuration.New()
	base.Set("base", "yes")

	cfg, gotInput := ResolveInvokeOptions(base)

	assert.Empty(t, gotInput)
	assert.Equal(t, "yes", cfg.GetString("base"))
}
