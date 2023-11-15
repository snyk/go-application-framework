package workflow

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
)

// EngineImpl is the default implementation of the Engine interface.
type EngineImpl struct {
	extensionInitializer []ExtensionInit
	workflows            map[string]Entry
	config               configuration.Configuration
	analytics            analytics.Analytics
	networkAccess        networking.NetworkAccess
	initialized          bool
	invocationCounter    int
	logger               *zerolog.Logger
	ui                   ui.UserInterface
	runtimeInfo          RuntimeInfo
}

var _ Engine = (*EngineImpl)(nil)

func (e *EngineImpl) GetLogger() *zerolog.Logger {
	return e.logger
}

func (e *EngineImpl) SetLogger(logger *zerolog.Logger) {
	e.logger = logger

	if e.networkAccess != nil {
		e.networkAccess.SetLogger(logger)
	}
}

func (e *EngineImpl) SetConfiguration(config configuration.Configuration) {
	e.config = config

	if e.networkAccess != nil {
		e.networkAccess.SetConfiguration(config)
	}
}

// NewWorkflowIdentifier creates a new workflow identifier represented in parsed URL format.
// It accepts a command param which is converted to a dot separated string and used as the host part of the URL.
func NewWorkflowIdentifier(command string) Identifier {
	dotSeparatedCommand := strings.ReplaceAll(command, " ", ".")
	id := url.URL{Scheme: "flw", Host: dotSeparatedCommand}
	return &id
}

// GetCommandFromWorkflowIdentifier returns the command string from a workflow identifier.
// It returns an empty string if the identifier is not a workflow identifier.
//
//goland:noinspection GoUnusedExportedFunction
func GetCommandFromWorkflowIdentifier(id Identifier) string {
	if id != nil && id.Scheme == "flw" {
		spaceSeparatedCommand := strings.ReplaceAll(id.Host, ".", " ")
		return spaceSeparatedCommand
	} else {
		return ""
	}
}

// NewTypeIdentifier creates a new type identifier represented in parsed URL format.
// It accepts a workflow identifier and a data type string which is used as the path part of the URL.
func NewTypeIdentifier(workflowID Identifier, dataType string) Identifier {
	id := *workflowID
	id.Scheme = "tpe"
	id.Path = dataType
	return &id
}

// NewWorkFlowEngine is an implementation of the Engine interface.
// It is called when creating a new app engine via CreateAppEngine().
func NewWorkFlowEngine(configuration configuration.Configuration) Engine {
	engine := NewDefaultWorkFlowEngine()
	engine.SetConfiguration(configuration)
	return engine
}

// NewDefaultWorkFlowEngine is an implementation of the Engine interface.
func NewDefaultWorkFlowEngine() Engine {
	engine := &EngineImpl{
		workflows:            make(map[string]Entry),
		initialized:          false,
		extensionInitializer: make([]ExtensionInit, 0),
		invocationCounter:    0,
		logger:               &zlog.Logger,
		config:               configuration.New(),
		ui:                   ui.DefaultUi(),
	}
	return engine
}

// Init initializes the engine by setting up the necessary defaults.
func (e *EngineImpl) Init() error {
	var err error

	e.invocationCounter = 0
	_ = e.GetNetworkAccess()

	for i := range e.extensionInitializer {
		err = e.extensionInitializer[i](e)
		if err != nil {
			return err
		}
	}

	// later scan here for extension binaries

	if e.analytics == nil {
		e.analytics = e.initAnalytics()
	}

	if err == nil {
		e.initialized = true
	}

	return err
}

func (e *EngineImpl) initAnalytics() analytics.Analytics {
	a := analytics.New()
	a.SetIntegration(e.config.GetString(configuration.INTEGRATION_NAME), e.config.GetString(configuration.INTEGRATION_VERSION))
	a.SetApiUrl(e.config.GetString(configuration.API_URL))
	a.SetOrg(e.config.GetString(configuration.ORGANIZATION))
	a.SetClient(func() *http.Client {
		return e.networkAccess.GetHttpClient()
	})

	return a
}

// Register registers a new workflow entry with the engine.
// In order to register a workflow, the following parameters are required:
// - id: the workflow identifier
// - config: the configuration options for the workflow
// - entryPoint: the entry point function for the workflow
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
		err := e.config.AddFlagSet(flagset)
		if err != nil {
			return nil, err
		}
	}

	return entry, nil
}

// GetWorkflows returns a list of all registered workflows.
func (e *EngineImpl) GetWorkflows() []Identifier {
	var result []Identifier

	for k := range e.workflows {
		tmp, _ := url.Parse(k)
		result = append(result, tmp)
	}

	return result
}

// GetWorkflow returns the workflow entry for the given workflow identifier.
func (e *EngineImpl) GetWorkflow(id Identifier) (Entry, bool) {
	workflow, ok := e.workflows[id.String()]
	return workflow, ok
}

// Invoke invokes the workflow with the given identifier.
func (e *EngineImpl) Invoke(id Identifier) ([]Data, error) {
	return e.InvokeWithInputAndConfig(id, []Data{}, nil)
}

// InvokeWithInput invokes the workflow with the given identifier and input data.
func (e *EngineImpl) InvokeWithInput(id Identifier, input []Data) ([]Data, error) {
	return e.InvokeWithInputAndConfig(id, input, nil)
}

// InvokeWithConfig invokes the workflow with the given identifier and configuration.
func (e *EngineImpl) InvokeWithConfig(id Identifier, config configuration.Configuration) ([]Data, error) {
	return e.InvokeWithInputAndConfig(id, []Data{}, config)
}

// InvokeWithInputAndConfig invokes the workflow with the given identifier, input data and configuration.
func (e *EngineImpl) InvokeWithInputAndConfig(
	id Identifier,
	input []Data,
	config configuration.Configuration,
) ([]Data, error) {
	var output []Data
	var err error

	if !e.initialized {
		return output, fmt.Errorf("workflow must be initialized with init() before it can be invoked")
	}

	workflow, ok := e.GetWorkflow(id)
	if ok {
		callback := workflow.GetEntryPoint()
		if callback != nil {
			e.invocationCounter++

			// prepare logger
			prefix := fmt.Sprintf("%s:%d", id.Host, e.invocationCounter)
			zlogger := e.logger.With().Str("ext", prefix).Logger()

			// prepare configuration
			if config == nil {
				config = e.config.Clone()
			}

			// create a context object for the invocation
			context := NewInvocationContext(id, config, e, e.networkAccess, zlogger, e.analytics, e.ui)

			// invoke workflow through its callback
			output, err = callback(context, input)
		}
	} else {
		err = fmt.Errorf("workflow '%v' not found", id)
	}

	return output, err
}

// GetAnalytics returns the analytics object.
func (e *EngineImpl) GetAnalytics() analytics.Analytics {
	return e.analytics
}

// GetNetworkAccess returns the network access object.
func (e *EngineImpl) GetNetworkAccess() networking.NetworkAccess {
	if e.networkAccess == nil {
		e.networkAccess = networking.NewNetworkAccess(e.config)
		e.networkAccess.SetLogger(e.logger)
	}

	return e.networkAccess
}

// AddExtensionInitializer adds an extension initializer to the engine.
func (e *EngineImpl) AddExtensionInitializer(initializer ExtensionInit) {
	e.extensionInitializer = append(e.extensionInitializer, initializer)
}

// GetConfiguration returns the configuration object.
func (e *EngineImpl) GetConfiguration() configuration.Configuration {
	return e.config
}

func (e *EngineImpl) GetUserInterface() ui.UserInterface {
	return e.ui
}

func (e *EngineImpl) SetUserInterface(userInterface ui.UserInterface) {
	e.ui = userInterface
}

func (e *EngineImpl) GetRuntimeInfo() RuntimeInfo {
	return e.runtimeInfo
}

func (e *EngineImpl) SetRuntimeInfo(ri RuntimeInfo) {
	e.runtimeInfo = ri
}

// GetGlobalConfiguration returns the global configuration options.
//
//goland:noinspection GoUnusedExportedFunction
func GetGlobalConfiguration() ConfigurationOptions {
	globalFLags := pflag.NewFlagSet("global", pflag.ContinueOnError)
	globalFLags.String(configuration.ORGANIZATION, "", "")
	globalFLags.BoolP(configuration.DEBUG, "d", false, "")
	globalFLags.Bool(configuration.INSECURE_HTTPS, false, "")
	return ConfigurationOptionsFromFlagset(globalFLags)
}
