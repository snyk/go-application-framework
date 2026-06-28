// Command exampleplugin is a minimal Snyk CLI extension. It is the canonical
// example of how an extension author uses the SDK and is also exercised by the
// loader's end-to-end tests.
//
// An extension is a standalone binary whose main() registers workflows and
// calls extension.Serve. Each workflow handler is an ordinary workflow.Callback:
// it receives a workflow.InvocationContext (configuration, authenticated network
// access, logger, UI) and returns workflow.Data.
package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/extension"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func main() {
	extension.Serve(func(r extension.Registrar) {
		// A simple workflow that reads a configuration flag.
		greetFlags := pflag.NewFlagSet("hello", pflag.ContinueOnError)
		greetFlags.String("name", "world", "who to greet")
		r.Register("flw://hello", greet, extension.WithFlags(greetFlags))

		// A workflow that calls the Snyk API using the host's authenticated
		// network access. The extension never sees the user's credentials; the
		// host injects them (see the "option C" auth proxy in the design doc).
		r.Register("flw://hello.fetch", fetch)
	})
}

func greet(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
	message := "hello " + ictx.GetConfiguration().GetString("name")
	return []workflow.Data{
		workflow.NewData(id, "text/plain", []byte(message)),
	}, nil
}

func fetch(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	client := ictx.GetNetworkAccess().GetHttpClient()

	// Build the request URL from the API endpoint exactly as in-process
	// workflows do. The host transparently routes it through its authenticated
	// network access.
	url := config.GetString(configuration.API_URL) + "/echo"
	resp, err := client.Get(url) //nolint:noctx // example brevity
	if err != nil {
		return nil, fmt.Errorf("calling api: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading api response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status %d: %s", resp.StatusCode, body)
	}

	id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello.fetch"), "response")
	return []workflow.Data{
		workflow.NewData(id, "application/json", body),
	}, nil
}
