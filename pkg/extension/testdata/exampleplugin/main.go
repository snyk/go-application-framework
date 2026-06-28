// Command exampleplugin is a minimal Snyk CLI extension used by the loader's
// end-to-end test. It is also the canonical example of how an extension author
// uses the SDK: define workflows, hand them to extension.Serve, and that's the
// whole binary.
package main

import (
	"context"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/extension"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func main() {
	extension.Serve(func(r extension.Registrar) {
		flags := pflag.NewFlagSet("hello", pflag.ContinueOnError)
		flags.String("name", "world", "who to greet")
		r.Register("flw://hello", greet, extension.WithFlags(flags))
	})
}

// greet returns a plain-text greeting built from the "name" configuration value
// the host exported.
func greet(_ context.Context, config configuration.Configuration, _ []workflow.Data) ([]workflow.Data, error) {
	id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
	message := "hello " + config.GetString("name")
	return []workflow.Data{
		workflow.NewData(id, "text/plain", []byte(message)),
	}, nil
}
