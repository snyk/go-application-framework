package devtools

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/cobra"
)

// Cmd is a helper utility for extension authors to define a lightweight CLI to
// test their extensions outside of the main Snyk CLI.
func Cmd(initializers ...workflow.ExtensionInit) (*cobra.Command, error) {
	// Initialize the engine with the given workflows
	logger := zerolog.New(os.Stderr)
	engine := app.CreateAppEngineWithOptions(
		app.WithZeroLogger(&logger),
		app.WithConfiguration(configuration.New()),
		app.WithInitializers(initializers...),
	)
	if err := engine.Init(); err != nil {
		return nil, err
	}

	// Build command tree
	root := newNode("snyk")
	for _, w := range engine.GetWorkflows() {
		fullCmd := workflow.GetCommandFromWorkflowIdentifier(w)
		parts := strings.Fields(fullCmd)
		root.add(parts, w)
	}
	rootCmd := root.cmd(engine)
	globalConfig := workflow.GetGlobalConfiguration()
	globalFlags := workflow.FlagsetFromConfigurationOptions(globalConfig)
	rootCmd.PersistentFlags().AddFlagSet(globalFlags)

	return rootCmd, nil
}
