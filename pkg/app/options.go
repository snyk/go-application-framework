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

// WithConfiguration replaces the engine's configuration. If an earlier option
// (e.g. WithExtensionPaths) already recorded extension paths on the engine's
// current configuration, they are carried forward onto the new one -- otherwise
// they would be silently discarded when the configuration object is swapped.
// The merge is deduplicated: without it, a path present on both the prior and
// new configuration would have the Loader launch two subprocesses for the
// same binary and register duplicate proxy workflows.
func WithConfiguration(config configuration.Configuration) Opts {
	return func(engine workflow.Engine) {
		if existing := engine.GetConfiguration(); existing != nil {
			if paths := existing.GetStringSlice(extension.ConfigurationKeyPaths); len(paths) > 0 {
				merged := append(config.GetStringSlice(extension.ConfigurationKeyPaths), paths...)
				config.Set(extension.ConfigurationKeyPaths, utils.Dedupe(merged))
			}
		}
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
// CLI flag or environment variable bound to that key. Duplicates (e.g. a path
// already present from a prior WithExtensionPaths call, or already set via
// flag/env) are removed, so the Loader never launches two subprocesses for
// the same binary.
func WithExtensionPaths(paths ...string) Opts {
	return func(engine workflow.Engine) {
		config := engine.GetConfiguration()
		if config == nil {
			return
		}
		existing := config.GetStringSlice(extension.ConfigurationKeyPaths)
		config.Set(extension.ConfigurationKeyPaths, utils.Dedupe(append(existing, paths...)))
	}
}
