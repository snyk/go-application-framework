package devtools_test

import (
	"fmt"
	"log"

	"github.com/snyk/go-application-framework/pkg/devtools"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var helloWorkflowID = workflow.NewWorkflowIdentifier("hello")

func helloWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	fmt.Println("Hello, workflow!")

	return []workflow.Data{}, nil
}

func initHelloWorkflow(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-hello", pflag.ExitOnError)
	c := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(helloWorkflowID, c, helloWorkflow); err != nil {
		return fmt.Errorf("error while registering 'hello' workflow: %w", err)
	}
	return nil
}

func ExampleCmd() {
	// Initialize the command with one or more workflows
	root, err := devtools.Cmd(initHelloWorkflow)
	if err != nil {
		log.Fatal(err)
	}

	// This is just for testing. In normal usage, args are set automatically
	// from os.Args.
	root.SetArgs([]string{"hello"})

	// Execute the command.
	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
	// Output: Hello, workflow!
}
