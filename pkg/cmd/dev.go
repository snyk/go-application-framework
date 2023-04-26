package cmd

import (
	"log"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/cobra"
)

// Dev is a helper utility for extension authors to define a lightweight CLI to
// test their extensions outside of the main Snyk CLI.
func Dev(initializers ...workflow.ExtensionInit) (*cobra.Command, error) {
	// Initialize the engine with the given workflows
	logger := log.New(os.Stderr, "", 0)
	engine := app.CreateAppEngineWithLogger(logger)
	engine.SetConfiguration(configuration.New())
	for _, i := range initializers {
		engine.AddExtensionInitializer(i)
	}
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
