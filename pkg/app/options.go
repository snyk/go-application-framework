package app

import (
	"log"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/extension"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

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

// WithExtensionPaths registers out-of-process extension binaries to be loaded
// when the engine initializes. The paths are stored on the configuration under
// extension.ConfigurationKeyPaths, so they can equivalently be supplied via a
// CLI flag or environment variable bound to that key.
func WithExtensionPaths(paths ...string) Opts {
	return func(engine workflow.Engine) {
		config := engine.GetConfiguration()
		if config == nil {
			return
		}
		existing := config.GetStringSlice(extension.ConfigurationKeyPaths)
		config.Set(extension.ConfigurationKeyPaths, append(existing, paths...))
	}
}
