package app

import (
	"log"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/machineid"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// machineIDResolveOptionsKey stashes the ResolveOption slice passed to WithMachineIDOptions on the
// engine's Configuration until initConfiguration reads it back to build the MACHINE_ID default
// value function. Configuration.Set only persists a value to Storage for a key registered via
// AddDefaultValue, so this key never round-trips through snyk.json.
const machineIDResolveOptionsKey = "internal_gaf_app_machineid_resolve_options"

type Opts func(engine workflow.Engine)

func WithLogger(logger *log.Logger) Opts {
	return func(engine workflow.Engine) {
		console := &zerolog.ConsoleWriter{
			Out:        &utils.ToLog{Logger: logger},
			NoColor:    true,
			PartsOrder: []string{zerolog.MessageFieldName},
		}
		log := zerolog.New(console)
		engine.SetLogger(&log)
	}
}

func WithConfiguration(config configuration.Configuration) Opts {
	return func(engine workflow.Engine) {
		engine.SetConfiguration(config)
	}
}

func WithZeroLogger(logger *zerolog.Logger) Opts {
	return func(engine workflow.Engine) {
		engine.SetLogger(logger)
	}
}

func WithInitializers(initializers ...workflow.ExtensionInit) Opts {
	return func(engine workflow.Engine) {
		for _, i := range initializers {
			engine.AddExtensionInitializer(i)
		}
	}
}

func WithRuntimeInfo(ri runtimeinfo.RuntimeInfo) Opts {
	return func(engine workflow.Engine) {
		engine.SetRuntimeInfo(ri)
	}
}

// WithMachineIDOptions passes additional machineid.ResolveOption values through to the
// machineid.Resolve default value function CreateAppEngineWithOptions wires up for
// configuration.MACHINE_ID. If also using WithConfiguration, pass WithConfiguration first: this
// option stores its argument on the engine's current Configuration.
func WithMachineIDOptions(opts ...machineid.ResolveOption) Opts {
	return func(engine workflow.Engine) {
		config := engine.GetConfiguration()
		if config == nil {
			return
		}
		existing, _ := config.Get(machineIDResolveOptionsKey).([]machineid.ResolveOption) //nolint:errcheck // zero-value fallback on absence/type-mismatch is intentional
		config.Set(machineIDResolveOptionsKey, append(existing, opts...))
	}
}

func WithPostInvokeHooks(hooks ...workflow.PostInvokeHook) Opts {
	return func(engine workflow.Engine) {
		for _, h := range hooks {
			if err := workflow.AddPostInvokeHook(engine, h); err != nil {
				engine.GetLogger().Warn().Err(err).Msg("failed to add post-invoke hook")
			}
		}
	}
}
