package workflow

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/spf13/pflag"
)

type EngineImpl struct {
	extensionInitializer []ExtensionInit
	workflows            map[string]Entry
	config               configuration.Configuration
	analytics            analytics.Analytics
	networkAccess        networking.NetworkAccess
	initialized          bool
}

func NewWorkflowIdentifier(command string) Identifier {
	dotSeparatedCommand := strings.ReplaceAll(command, " ", ".")
	id := url.URL{Scheme: "flw", Host: dotSeparatedCommand}
	return &id
}

func GetCommandFromWorkflowIdentifier(id Identifier) string {
	if id != nil && id.Scheme == "flw" {
		spaceSeparatedCommand := strings.ReplaceAll(id.Host, ".", " ")
		return spaceSeparatedCommand
	} else {
		return ""
	}
}

func NewTypeIdentifier(workflowID Identifier, dataType string) Identifier {
	id := *workflowID
	id.Scheme = "tpe"
	id.Path = dataType
	return &id
}

func NewWorkFlowEngine(configuration configuration.Configuration) Engine {
	engine := &EngineImpl{
		workflows:            make(map[string]Entry),
		config:               configuration,
		initialized:          false,
		extensionInitializer: make([]ExtensionInit, 0),
	}
	return engine
}

func (e *EngineImpl) Init() error {
	var err error

	e.networkAccess = networking.NewNetworkAccess(e.config)

	for i := range e.extensionInitializer {
		err = e.extensionInitializer[i](e)
		if err != nil {
			return err
		}
	}

	// later scan here for extension binaries

	if e.analytics == nil {
		e.analytics = analytics.New()
		e.analytics.SetIntegration(e.config.GetString(configuration.INTEGRATION_NAME), e.config.GetString(configuration.INTEGRATION_VERSION))
		e.analytics.SetApiUrl(e.config.GetString(configuration.API_URL))
		e.analytics.SetOrg(e.config.GetString(configuration.ORGANIZATION))
		e.analytics.AddHeader(func() http.Header {
			url := e.config.GetUrl(configuration.API_URL)
			header := e.networkAccess.GetDefaultHeader(url)
			return header
		})
		e.analytics.SetClient(func() *http.Client {
			return e.networkAccess.GetHttpClient()
		})
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

	tmp := id.String()
	e.workflows[tmp] = entry

	flagset := FlagsetFromConfigurationOptions(config)
	if flagset != nil {
		e.config.AddFlagSet(flagset)
	}

	return entry, nil
}

func (e *EngineImpl) GetWorkflows() []Identifier {
	var result []Identifier

	for k := range e.workflows {
		tmp, _ := url.Parse(k)
		result = append(result, tmp)
	}

	return result
}

func (e *EngineImpl) GetWorkflow(id Identifier) (Entry, bool) {
	workflow, ok := e.workflows[id.String()]
	return workflow, ok
}

func (e *EngineImpl) Invoke(id Identifier) ([]Data, error) {
	return e.InvokeWithInputAndConfig(id, []Data{}, nil)
}

func (e *EngineImpl) InvokeWithInput(id Identifier, input []Data) ([]Data, error) {
	return e.InvokeWithInputAndConfig(id, input, nil)
}

func (e *EngineImpl) InvokeWithConfig(id Identifier, config configuration.Configuration) ([]Data, error) {
	return e.InvokeWithInputAndConfig(id, []Data{}, config)
}

func (e *EngineImpl) InvokeWithInputAndConfig(id Identifier, input []Data, config configuration.Configuration) ([]Data, error) {
	var output []Data
	var err error

	if e.initialized == false {
		return output, fmt.Errorf("Workflow must be initialized with init() before it can be invoked.")
	}

	workflow, ok := e.GetWorkflow(id)
	if ok {
		callback := workflow.GetEntryPoint()
		if callback != nil {
			// prepare logger
			logger := log.New(os.Stderr, id.Host+" - ", e.config.GetInt(configuration.DEBUG_FORMAT))
			if e.config.GetBool(configuration.DEBUG) == false {
				logger.SetOutput(io.Discard)
			}

			// prepare configuration
			if config == nil {
				config = e.config.Clone()
			}

			// create a context object for the invocation
			context := InvocationContextImpl{
				WorkflowID:     id,
				Configuration:  config,
				WorkflowEngine: e,
				networkAccess:  e.networkAccess,
				logger:         logger,
			}

			// invoke workflow through its callback
			output, err = callback(&context, input)
		}
	} else {
		err = fmt.Errorf("Workflow '%v' not found.", id)
	}

	return output, err
}

func (e *EngineImpl) GetAnalytics() analytics.Analytics {
	return e.analytics
}

func (e *EngineImpl) GetNetworkAccess() networking.NetworkAccess {
	return e.networkAccess
}

func (e *EngineImpl) AddExtensionInitializer(initializer ExtensionInit) {
	e.extensionInitializer = append(e.extensionInitializer, initializer)
}

func (e *EngineImpl) GetConfiguration() configuration.Configuration {
	return e.config
}

func GetGlobalConfiguration() ConfigurationOptions {
	globalFLags := pflag.NewFlagSet("global", pflag.ContinueOnError)
	globalFLags.String(configuration.ORGANIZATION, "", "")
	globalFLags.BoolP(configuration.DEBUG, "d", false, "")
	globalFLags.Bool(configuration.INSECURE_HTTPS, false, "")
	return ConfigurationOptionsFromFlagset(globalFLags)
}
