package analytics

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
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
	wrongType := struct{ InstrumentationCollector }{NewInstrumentationCollector()}

	err := SetPersona(wrongType, Persona{Agent: "cursor"})

	require.EqualError(t, err, "collector was not created by NewInstrumentationCollector")
}

func Test_SetPersona_rejectsAnInteractiveModeOutsideTheBitmask(t *testing.T) {
	for _, mode := range []int{-1, 8, 99} {
		t.Run(strconv.Itoa(mode), func(t *testing.T) {
			ic := NewInstrumentationCollector()

			err := SetPersona(ic, Persona{Agent: "cursor", InteractiveMode: mode})

			require.EqualError(t, err, fmt.Sprintf("interactive mode %d is outside 0 to 7", mode))
			body, err := GetV2InstrumentationObject(ic)
			require.NoError(t, err)
			assert.Nil(t, body.Data.Attributes.Interaction.Persona)
		})
	}
}

func Test_SetPersona_mutatingASerializedPersonaLeavesTheCollectorUnchanged(t *testing.T) {
	ic := NewInstrumentationCollector()
	require.NoError(t, SetPersona(ic, Persona{Agent: "cursor", AgentVersion: "1.0", Interactive: true, InteractiveMode: 7}))
	first, err := GetV2InstrumentationObject(ic)
	require.NoError(t, err)

	*first.Data.Attributes.Interaction.Persona.Agent = "changed"
	*first.Data.Attributes.Interaction.Persona.AgentVersion = "changed"
	*first.Data.Attributes.Interaction.Persona.Interactive = false
	*first.Data.Attributes.Interaction.Persona.InteractiveMode = "0"
	second, err := GetV2InstrumentationObject(ic)

	require.NoError(t, err)
	persona, err := json.Marshal(second.Data.Attributes.Interaction.Persona)
	require.NoError(t, err)
	assert.JSONEq(t, `{"agent": "cursor", "agent_version": "1.0", "interactive": true, "interactive_mode": "7"}`, string(persona))
}

func Test_SetPersona_isSafeAlongsideSerialization(t *testing.T) {
	ic := NewInstrumentationCollector()
	var wg sync.WaitGroup

	wg.Go(func() {
		for i := range 100 {
			assert.NoError(t, SetPersona(ic, Persona{Agent: "cursor", InteractiveMode: i % 8}))
		}
	})
	wg.Go(func() {
		for range 100 {
			_, err := GetV2InstrumentationObject(ic, WithConfiguration(configuration.NewWithOpts()))
			assert.NoError(t, err)
		}
	})
	wg.Wait()
}
