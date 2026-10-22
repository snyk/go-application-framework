package analytics

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_SetPersona(t *testing.T) {
	testCases := []struct {
		name     string
		persona  Persona
		expected string
	}{
		{
			name:     "agent with version on a terminal",
			persona:  Persona{Agent: "claude_code", AgentVersion: "2.1.233", Interactive: true, InteractiveMode: 7},
			expected: `{"agent": "claude_code", "agent_version": "2.1.233", "interactive": true, "interactive_mode": "7"}`,
		},
		{
			name:     "no agent and no terminal",
			persona:  Persona{},
			expected: `{"interactive": false, "interactive_mode": "0"}`,
		},
		{
			name:     "agent without version",
			persona:  Persona{Agent: "cursor", InteractiveMode: 6},
			expected: `{"agent": "cursor", "interactive": false, "interactive_mode": "6"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ic := NewInstrumentationCollector()

			require.NoError(t, SetPersona(ic, tc.persona))

			body, err := GetV2InstrumentationObject(ic)
			require.NoError(t, err)
			persona, err := json.Marshal(body.Data.Attributes.Interaction.Persona)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(persona))
		})
	}
}

func Test_SetPersona_leavesPersonaOutUntilSet(t *testing.T) {
	body, err := GetV2InstrumentationObject(NewInstrumentationCollector())

	require.NoError(t, err)
	assert.Nil(t, body.Data.Attributes.Interaction.Persona)
}

func Test_SetPersona_scrubsSecretShapedAgentsWhenConfigured(t *testing.T) {
	ic := NewInstrumentationCollector()
	require.NoError(t, SetPersona(ic, Persona{Agent: "Bearer abcdef123456", AgentVersion: "Bearer abcdef123456"}))

	body, err := GetV2InstrumentationObject(ic, WithConfiguration(configuration.NewWithOpts()))

	require.NoError(t, err)
	assert.Equal(t, "Bearer ***", *body.Data.Attributes.Interaction.Persona.Agent)
	assert.Equal(t, "Bearer ***", *body.Data.Attributes.Interaction.Persona.AgentVersion)
}

func Test_SetPersona_rejectsACollectorNotCreatedByGAF(t *testing.T) {
	err := SetPersona(nil, Persona{Agent: "cursor"})

	assert.Error(t, err)
}
