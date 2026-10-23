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

// SetPersona sets the persona sent as interaction.persona. It returns an error, and leaves the persona unchanged,
// for a collector not created by NewInstrumentationCollector or an InteractiveMode outside 0 to 7.
func SetPersona(collector InstrumentationCollector, p Persona) error {
	ic, ok := collector.(*instrumentationCollectorImpl)
	if !ok {
		return fmt.Errorf("collector was not created by NewInstrumentationCollector")
	}
	if p.InteractiveMode < 0 || p.InteractiveMode > 7 {
		return fmt.Errorf("interactive mode %d is outside 0 to 7", p.InteractiveMode)
	}

	ic.personaMu.Lock()
	defer ic.personaMu.Unlock()
	ic.persona = &p
	return nil
}

func toAPIPersona(p *Persona) *api.Persona {
	if p == nil {
		return nil
	}
	persona := &api.Persona{
		Interactive:     new(p.Interactive),
		InteractiveMode: new(strconv.Itoa(p.InteractiveMode)),
	}
	if p.Agent != "" {
		persona.Agent = new(p.Agent)
	}
	if p.AgentVersion != "" {
		persona.AgentVersion = new(p.AgentVersion)
	}
	return persona
}

func scrubPersona(p *api.Persona, dict logging.ScrubbingDict) {
	if p == nil {
		return
	}
	if p.Agent != nil {
		p.Agent = new(string(logging.ScrubValue([]byte(*p.Agent), dict)))
	}
	if p.AgentVersion != nil {
		p.AgentVersion = new(string(logging.ScrubValue([]byte(*p.AgentVersion), dict)))
	}
}
