package app

import (
	"log"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
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

func WithRuntimeInfo(name, version string) Opts {
	return func(engine workflow.Engine) {
		engine.SetRuntimeInfo(workflow.RuntimeInfo{
			AppName:    name,
			AppVersion: version,
		})
	}
}
