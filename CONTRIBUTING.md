# Contributing
This repo is intended for internal (Snyk) contributions only at this time.

# Creating a new extension
The `go-application-framework` makes it easy to add functionality to the Snyk CLI by taking care of the orchestration, requirements, and state management when running the CLI; this all happens behind the scenes via the packages provided by the framework. It means we can focus on building the core business logic for our extension and not worry about much else.

Creating a new extension using the `go-application-framework` can be done in three steps

1. Create the extension workflow
2. Register the extension with the workflow engine
3. Initialise the extension when using the `go-application-framework`

# Create the extension workflow
The extension workflow is the main component of your extension, it should:
1. Uniquely identify your workflow
2. Initialise your workflow (registering the extension with the workflow engine should happen here)
3. Have an entry point containing the extension business logic

# Creating `snyk whoami`
The `snyk whoami` command was created following the steps outlined above; the following outlines the extension implementation in detail.

## Uniquely identify your workflow
Before we can start creating our extension workflow, we'll need to create our workflow identifier. An identifier is required by the workflow engine to identify our workflow. The workflow identifier should also contain the name of the new extension command.

The framework's `workflow` package allows us to easily create an identifier in this format as follows:

```go
import "github.com/snyk/go-application-framework/pkg/workflow"

// define a new workflow identifier for this workflow
// this identifies the 'snyk whoami' command with the workflow engine
var workflowName = "whoami"
var WORKFLOWID_WHOAMI workflow.Identifier = workflow.NewWorkflowIdentifier(workflowName)
```

## Initialise your workflow
Now that we have a workflow identifier, we can continue with the implementation of the workflow's initialiser via an `Init()` function.

Here we want to initialise the extension workflow's configuration, as well as register the workflow with the workflow engine, which is passed to the function as a parameter.

```go
func Init(engine workflow.Engine) error {
	// initialise workflow configuration
	whoAmIConfig := pflag.NewFlagSet(workflowName, pflag.ExitOnError)
	// add json flag to configuration
	whoAmIConfig.Bool("json", false, "output in json format")

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_WHOAMI, workflow.ConfigurationOptionsFromFlagset(whoAmIConfig), whoAmIWorkflowEntryPoint)
	return err
}
```

### Initialise configuration
We use the `pflag` package in order to create POSIX/GNU-style --flags. The extension should support the `--json` flag, so we add it to the configuration via `whoAmIConfig.Bool()`.

### Mark experimental versions of an extension workflow
There is a common pattern to mark workflows as experimental by using [MarkAsExperimental()](https://github.com/snyk/go-application-framework/blob/main/pkg/local_workflows/config_utils/experimental.go#L28) in order to indicate early non production ready versions of a workflow. In the CLI this will automatically reflect in a required argument `--experimental`, if not provided the CLI will show an error and not call the workflow.

### Register with the workflow engine
Next we must register the extension with the workflow engine. The `workflow` package is used again here in, firstly to abstract away the engine/workflow registration logic via `engine.Register`, and again to configure the workflow's configuration via `workflow.ConfigurationOptionsFromFlagset`.

## Implement business logic via the workflow entry point
Now we can define the business logic for our extension workflow. This can be done in an `entryPoint()` function, which has two parameters; `invocationContext` and `input []workflow.Data`.

`invocationContext` is a `workflow.InvocationContext` type and it abstracts away much of the boilerplate required when implementing a new workflow, For example, it provides a wrapper around the `net/http` package via `GetNetWorkAccess()` and reduces its implementation mainly to supplying configuration parameters.

`input` is a `workflow.Data` type and is the standardised data interface used by all extensions workflows.

At a high level, the business logic for the extension workflow will be as follows:
1. Get necessary objects from the invocation context
2. Call the `/user/me` Snyk API endpoint
3. Extract the `username` property from the API response
4. Return the `username`

Additionally, we want to support the `--json` flag, when supplied, it should return the full API response.

Implementing all this, the `entryPoint()` will look like:

```go
func entryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()

	logger.Println("whoAmI workflow start")

	// define userme API endpoint
	baseUrl := config.GetString(configuration.API_URL)
	url := baseUrl + apiVersion + endpoint

	// call userme API endpoint
	userMe, err := fetchUserMe(httpClient, url, logger)
	if err != nil {
		return nil, fmt.Errorf("error while fetching user: %w", err)
	}

	// extract user from response
	user, err := extractUser(userMe, logger)
	if err != nil {
		return nil, fmt.Errorf("error while extracting user: %w", err)
	}

	// return full payload if json flag is set
	if config.GetBool("json") {
		// parse response
		userMeData := createWorkflowData(userMe, "application/json")

		// return userme data
		return []workflow.Data{userMeData}, err
	}

	userData := createWorkflowData(user, "text/plain")
	return []workflow.Data{userData}, err
}
```

### Get necessary invocation context objects
The first step is to retrieve the necessary objects the workflow requires.
- `invocationCtx.GetConfiguration()` will return the configuration object; which contains, amongst other things, the flags set in our `Init()` function
- `invocationCtx.GetLogger()` will return a logger instance passed to the workflow engine during setup
- `invocationCtx.GetNetworkAccess().GetHttpClient()` returns a httpClient which we can use to make Snyk API requests

### Call the `/user/me` Snyk API endpoint
The next step is to fetch the user info by calling the `/user/me` endpoint, The `fetchUserMe()` function makes the API request and returns the response body

### Extract the username property from the API response
Next, we must parse the response and extract the `username` property. The `extractUser()` function handles this

### Return the username
The last step is to return the username. The workflow engine expects a `[]]workflow.Data` type in the `entryPoint()` response, so we must create a response of this type. The `createWorkflowData()` function handles this

```go
func createWorkflowData(data interface{}, contentType string) workflow.Data {
	return workflow.NewData(
		// use new type identifier when creating new data
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, workflowName),
		contentType,
		data,
	)
}
```

`workflow.NewData()` creates a `workflow.Data` instance. Note that `workflow.NewData()` requires a new type identifier, which we create using `workflow.NewTypeIdentifier()`

### Support `--json` flag
As an additional functionality, we want to support the `--json` flag so that when we run `snyk whoami --json` we will return the full JSON payload from the `/user/me` endpoint

Using the `config` object retrieved from `workflow.GetConfiguration()`, we can check if the flag is set using `config.GetBool("json")`, we can then return the full payload response using hte `createWorkflowData()` helper function

# Initialise extension when using the `go-application-framework`
The final step is to add the extension to the CLI, this is done in the [CLI](https://github.com/snyk/cli/blob/master/cliv2/cmd/cliv2/main.go) itself.

```go
// cliv2/cmd/cliv2/main.go
import (
  "github.com/snyk/go-application-framework/pkg/app"
  "github.com/snyk/go-application-framework/pkg/workflow"
  "github.com/snyk/whoami-cli-extension/pkg/whoami"
)

func MainWithErrorCode() int {
	// ...

	// create engine
	engine = app.CreateAppEngine()
	config = engine.GetConfiguration()
	config.AddFlagSet(rootCommand.LocalFlags())

	debugEnabled := config.GetBool(configuration.DEBUG)
	debugLogger := getDebugLogger(config)

	if noProxyAuth := config.GetBool(basic_workflows.PROXY_NOAUTH); noProxyAuth {
		config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.NoAuth))
	}

	// initialize the extensions -> they register themselves at the engine
	engine.AddExtensionInitializer(basic_workflows.Init)
	engine.AddExtensionInitializer(sbom.Init)
	engine.AddExtensionInitializer(whoami.Init)

	// init engine
	err = engine.Init()
	if err != nil {
		debugLogger.Println("Failed to init Workflow Engine!", err)
		return constants.SNYK_EXIT_CODE_ERROR
	}
  
  // ...
}
```
As you can see, adding our extension to the CLI is as simple as calling the `engine.AddExtensionInitializer()` function and passing our extension's `Init()` in as a parameter.

That's it!

# UFM test fixtures

The presenter tests in `internal/presenters/` compare rendered output against expected files stored under `internal/presenters/testdata/ufm/`. There are several workflows for keeping these up to date.

## Generating a fixture (recommended)

Use the helper target to run a scan, dump workflow payloads to disk, pick the latest `workflow.TestResult.*`, add a `.json` extension, and optionally redact in one flow:

```bash
# Defaults:
# - SNYK_BIN=snyk
# - OUT_DIR=./dumps
# - DUMP_DIR=<OUT_DIR>/raw
# - default scan: secrets test . (override with SCAN_CMD="...")
# - REPORT=0 (set REPORT=1 to append --report, only for commands that support it)
# - REDACT=1
make generate-fixture \
  PROJECT=/path/to/scanned-repo \
  ORG=my-org \
  NAME=secrets_with_report \
  REPORT=1
```

Output files:

- `./dumps/<name>.testresult.raw.json` (non-redacted dump copy)
- `./dumps/<name>.testresult.json` (redacted, when `REDACT=1`)

Useful overrides:

```bash
# Use a custom CLI binary and disable redaction
make generate-fixture \
  PROJECT=/path/to/scanned-repo \
  ORG=my-org \
  NAME=secrets_with_report \
  SNYK_BIN=/path/to/snyk-macos-arm64 \
  REDACT=0

# Customize where dump files and final outputs are written
make generate-fixture \
  PROJECT=/path/to/scanned-repo \
  ORG=my-org \
  NAME=secrets_with_report \
  DUMP_DIR=/tmp/my-dump-dir \
  OUT_DIR=/tmp/my-fixtures
```

The dump command uses these internal settings by default:

- `SNYK_TMP_PATH=<DUMP_DIR>`
- `INTERNAL_IN_MEMORY_THRESHOLD_BYTES=1`
- `INTERNAL_CLEANUP_GLOBAL_TEMP_DIR_ENABLED=false`

If the printed command shows `snyk test .` instead of `snyk secrets test .`, your shell may have `SCAN_CMD` exported. Run `unset SCAN_CMD` or pass `SCAN_CMD="secrets test ."` explicitly.

## Redacting a dump into a stable fixture

To redact an existing dump file manually:

```bash
go run ./cmd/ufm-fixture-tool \
  --input=./dumps/raw/workflow.TestResult.12345 \
  --output=./internal/presenters/testdata/ufm/my_fixture.testresult.json

# Or via make (OUTPUT is optional)
make redact-fixture INPUT=./dumps/raw/workflow.TestResult.12345 OUTPUT=./path/to/fixture.testresult.json
```

If `OUTPUT` is omitted, the redaction tool writes `<input>_redacted.json` next to the input path.


## Regenerating expected files from existing fixtures

If you changed a presenter template and need to update the expected SARIF / human-readable output without re-fetching from the API:

```bash
make regenerate-expected
```

This runs the presenter tests with `UFM_REGEN=1`, which overwrites the expected files with the current presenter output and skips the comparison. Review the diff before committing.
