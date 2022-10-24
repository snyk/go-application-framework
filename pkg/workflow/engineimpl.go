package workflow

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type EngineImpl struct {
	workflows   map[Identifier]Entry
	config      configuration.Configuration
	analytics   *analytics.Analytics
	initialized bool
}

func NewWorkflowIdentifier(command string) Identifier {
	dotSeparatedCommand := strings.ReplaceAll(command, " ", ".")
	id := url.URL{Scheme: "flw", Host: dotSeparatedCommand}
	return &id
}

func NewTypeIdentifier(workflowID Identifier, dataType string) Identifier {
	id := *workflowID
	id.Scheme = "tpe"
	id.Path = dataType
	return &id
}

func NewWorkFlowEngine(configuration configuration.Configuration) Engine {
	engine := &EngineImpl{
		workflows:   make(map[Identifier]Entry),
		config:      configuration,
		initialized: false,
	}
	return engine
}

func (e *EngineImpl) Init() error {
	var err error

	if e.analytics == nil {
		e.analytics = analytics.New()
	}

	if err == nil {
		e.initialized = true
	}

	return err
}

func (e *EngineImpl) Register(id Identifier, config ConfigurationOptions, entryPoint Callback) (Entry, error) {
	if entryPoint == nil {
		return nil, fmt.Errorf("EntryPoint must not be nil")
	}

	if config == nil {
		return nil, fmt.Errorf("Config must not be nil")
	}

	if id == nil {
		return nil, fmt.Errorf("ID must not be nil")
	}

	entry := &EntryImpl{
		visible:        true,
		expectedConfig: config,
		entryPoint:     entryPoint,
	}
	e.workflows[id] = entry

	return entry, nil
}

func (e *EngineImpl) GetWorkflows() []Identifier {
	var result []Identifier

	for k := range e.workflows {
		result = append(result, k)
	}

	return result
}

func (e *EngineImpl) GetWorkflow(id Identifier) (Entry, bool) {
	workflow, ok := e.workflows[id]
	return workflow, ok
}

func (e *EngineImpl) Invoke(id Identifier) ([]Data, error) {
	var input []Data
	return e.InvokeWithInput(id, input)
}

func (e *EngineImpl) InvokeWithInput(id Identifier, input []Data) ([]Data, error) {
	var output []Data
	var err error

	if e.initialized == false {
		return output, fmt.Errorf("Workflow must be initialized with init() before it can be invoked.")
	}

	workflow, ok := e.GetWorkflow(id)
	if ok {
		callback := workflow.GetEntryPoint()
		if callback != nil {
			// create a context object for the invocation
			context := InvocationContextImpl{
				WorkflowID:     id,
				Configuration:  e.config.Clone(),
				WorkflowEngine: e,
			}

			// invoke workflow through its callback
			output, err = callback(&context, input)
			if err != nil {
				err = errors.Wrapf(err, "Callback failed for '%s'", id.String())
			}
		}
	} else {
		err = fmt.Errorf("Workflow '%v' not found.", id)
	}

	return output, err
}

func (e *EngineImpl) GetAnalytics() *analytics.Analytics {
	return e.analytics
}
