package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewProvider_unknownProvider(t *testing.T) {
	_, err := NewProvider(Options{Provider: "skynet", Model: "some-model"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skynet")
}

func Test_NewProvider_requiresModel(t *testing.T) {
	_, err := NewProvider(Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func Test_NewProvider_defaultsToOllama(t *testing.T) {
	provider, err := NewProvider(Options{Model: "gemma3:4b"})
	require.NoError(t, err)
	assert.NotNil(t, provider)
}

func Test_BuildPrompt(t *testing.T) {
	report := "Snyk Doctor Diagnostic Report\nsome diagnostic content"
	prompt := BuildPrompt(report)

	assert.Contains(t, prompt, report)
	assert.Contains(t, prompt, "title")
	assert.Contains(t, prompt, "rootCause")
	assert.Contains(t, prompt, "evidence")
	assert.Contains(t, prompt, "suggestedFix")
}

func Test_ParseDiagnosis_structured(t *testing.T) {
	response := `{"title":"Not authenticated","rootCause":"No token.","evidence":["line 6: 401"],"suggestedFix":["Run snyk auth.","Retry the scan."]}`

	diagnosis := ParseDiagnosis(response)

	assert.Equal(t, "Not authenticated", diagnosis.Title)
	assert.Equal(t, "No token.", diagnosis.RootCause)
	require.Len(t, diagnosis.Evidence, 1)
	assert.Equal(t, Steps{"Run snyk auth.", "Retry the scan."}, diagnosis.SuggestedFix)
	assert.Empty(t, diagnosis.Raw)
}

func Test_ParseDiagnosis_fixAsSingleString(t *testing.T) {
	response := `{"title":"Not authenticated","rootCause":"No token.","evidence":[],"suggestedFix":"Run snyk auth."}`

	diagnosis := ParseDiagnosis(response)

	assert.Equal(t, Steps{"Run snyk auth."}, diagnosis.SuggestedFix)
}

func Test_ParseDiagnosis_jsonWithSurroundingText(t *testing.T) {
	response := "Here is the diagnosis:\n{\"title\":\"Proxy misconfigured\",\"rootCause\":\"x\",\"evidence\":[],\"suggestedFix\":\"y\"}\nHope this helps!"

	diagnosis := ParseDiagnosis(response)

	assert.Equal(t, "Proxy misconfigured", diagnosis.Title)
	assert.Empty(t, diagnosis.Raw)
}

func Test_ParseDiagnosis_fallbackToRaw(t *testing.T) {
	response := "The problem is probably your token.\nTry snyk auth."

	diagnosis := ParseDiagnosis(response)

	assert.Empty(t, diagnosis.Title)
	assert.Equal(t, response, diagnosis.Raw)
}
