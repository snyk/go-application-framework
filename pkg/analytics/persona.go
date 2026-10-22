package analytics

import (
	"fmt"
	"strconv"

	api "github.com/snyk/go-application-framework/internal/api/analytics/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/logging"
)

// Persona describes who or what drives an interaction. The producer detects it, since only the producer
// knows whether its standard streams belong to a user's terminal.
type Persona struct {
	// Agent is the canonical name of the coding agent driving the interaction, empty when none was detected.
	Agent string
	// AgentVersion is the agent's version, empty when unknown.
	AgentVersion string
	Interactive  bool
	// InteractiveMode is a bitmask of the standard streams attached to a terminal: stdin 1, stdout 2, stderr 4.
	InteractiveMode int
}

// SetPersona sets the persona sent as interaction.persona. It returns an error for a collector not created by NewInstrumentationCollector.
func SetPersona(collector InstrumentationCollector, p Persona) error {
	ic, ok := collector.(*instrumentationCollectorImpl)
	if !ok {
		return fmt.Errorf("failed to convert collector")
	}

	persona := &api.Persona{
		Interactive:     &p.Interactive,
		InteractiveMode: new(strconv.Itoa(p.InteractiveMode)),
	}
	if p.Agent != "" {
		persona.Agent = &p.Agent
	}
	if p.AgentVersion != "" {
		persona.AgentVersion = &p.AgentVersion
	}
	ic.persona = persona
	return nil
}

// scrubPersona returns a copy, so scrubbing never alters the persona the collector holds.
func scrubPersona(p *api.Persona, dict logging.ScrubbingDict) *api.Persona {
	if p == nil {
		return nil
	}
	scrubbed := *p
	if p.Agent != nil {
		scrubbed.Agent = new(string(logging.ScrubValue([]byte(*p.Agent), dict)))
	}
	if p.AgentVersion != nil {
		scrubbed.AgentVersion = new(string(logging.ScrubValue([]byte(*p.AgentVersion), dict)))
	}
	return &scrubbed
}
