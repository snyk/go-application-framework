// Command whoami is an example dynamic extension. It adds a `whoami` command
// that delegates to the host's built-in whoami workflow — showing how an
// extension can call other workflows on the host (with the host's
// authentication) instead of reimplementing them.
//
// Build it with `make build-examples`, then run the CLI with
// `--plugin-path .bin/whoami`. See docs/dynamic-extensions.md.
package main

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/extension"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func main() {
	extension.Serve(func(r extension.Registrar) {
		// Registered under its own identifier so it doesn't collide with the
		// host's built-in "whoami".
		r.Register("flw://example.whoami", run)
	})
}

func run(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	engine := ictx.GetEngine()
	if engine == nil {
		return nil, fmt.Errorf("host engine is not available to this extension")
	}

	// Invoke the host's built-in whoami workflow. It runs on the host with the
	// user's authentication, and we pass its result straight back.
	result, err := engine.Invoke(workflow.NewWorkflowIdentifier("whoami"))
	if err != nil {
		return nil, fmt.Errorf("calling the host whoami workflow: %w", err)
	}
	return result, nil
}
