package localworkflows

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var (
	WORKFLOWID_DEPGRAPH_WORKFLOW workflow.Identifier = OpenSourceDepGraph.Identifier()
	DATATYPEID_DEPGRAPH          workflow.Identifier = OpenSourceDepGraph.TypeIdentifier()

	genericFlags = genericDepGraphFlags{
		Debug: workflow.Flag[bool]{Name: configuration.DEBUG, DefaultValue: false},
	}

	// The depgraph workflow is responsible for handling the depgraph data
	// As part of the localworkflows package, it is registered via the localworkflows.Init method
	OpenSourceDepGraph = &osDepGraphWorkflow{
		Workflow: &workflow.Workflow{
			Name:     "depgraph",
			Visible:  false,
			TypeName: "depgraph",
			Flags: OpenSourceDepGraphFlags{
				genericDepGraphFlags: genericFlags,
				AllProjects: workflow.Flag[bool]{
					Name:         "all-projects",
					Usage:        "Auto-detect all projects in the working directory (including Yarn workspaces).",
					DefaultValue: false,
				},
				FailFast: workflow.Flag[bool]{
					Name:         "fail-fast",
					Usage:        "Fail fast when scanning all projects",
					DefaultValue: false,
				},
				Exclude: workflow.Flag[string]{
					Name:         "exclude",
					Usage:        "Can be used with --all-projects to indicate directory Names and file Names to exclude. Must be comma separated.",
					DefaultValue: "",
				},
				DetectionDepth: workflow.Flag[string]{
					Name: "detection-depth",
					Usage: "Use with --all-projects to indicate how many subdirectories to search. " +
						"DEPTH must be a number, 1 or greater; zero (0) is the current directory.",
					DefaultValue: "",
				},
				Dev: workflow.Flag[bool]{
					Name:         "dev",
					Usage:        "Include dev dependencies",
					DefaultValue: false,
				},
				PruneRepeatedSubdependencies: workflow.Flag[bool]{
					Name:         "prune-repeated-subdependencies",
					Shorthand:    "p",
					DefaultValue: false,
					Usage:        "Prune dependency trees, removing duplicate sub-dependencies.",
				},
				Unmanaged: workflow.Flag[bool]{
					Name:         "unmanaged",
					Usage:        "For C/C++ only, scan all files for known open source dependencies and build an SBOM.",
					DefaultValue: false,
				},
				// file is only relevant for OS, in container the `Dockerfile` could be specified, but
				// doesn't really influence the results (only the advice).
				File: workflow.Flag[string]{
					Name:         "file",
					Usage:        "Specify a package file.",
					DefaultValue: "",
				},
			},
		},
	}
)

// InitDepGraphWorkflow initializes the depgraph workflow
// The depgraph workflow is responsible for handling the depgraph data
// As part of the localworkflows package, it is registered via the localworkflows.Init method
// Deprecated: use `workflow.Register(OpenSourceDepGraph, engine)` directly.
func InitDepGraphWorkflow(engine workflow.Engine) error {
	return workflow.Register(OpenSourceDepGraph, engine)
}

type osDepGraphWorkflow struct {
	*workflow.Workflow
}

func (o osDepGraphWorkflow) Flags() OpenSourceDepGraphFlags {
	return o.Workflow.Flags.(OpenSourceDepGraphFlags)
}

type genericDepGraphFlags struct {
	Debug workflow.Flag[bool]
}

func (g genericDepGraphFlags) GetFlags() workflow.Flags {
	return workflow.Flags{g.Debug}
}

type OpenSourceDepGraphFlags struct {
	genericDepGraphFlags

	AllProjects                  workflow.Flag[bool]
	DetectionDepth               workflow.Flag[string]
	Exclude                      workflow.Flag[string]
	FailFast                     workflow.Flag[bool]
	Dev                          workflow.Flag[bool]
	File                         workflow.Flag[string]
	PruneRepeatedSubdependencies workflow.Flag[bool]
	Unmanaged                    workflow.Flag[bool]
}

func (o OpenSourceDepGraphFlags) GetFlags() workflow.Flags {
	return append(
		o.genericDepGraphFlags.GetFlags(),
		o.AllProjects,
		o.DetectionDepth,
		o.Dev,
		o.Exclude,
		o.FailFast,
		o.File,
		o.PruneRepeatedSubdependencies,
		o.Unmanaged,
	)
}

func (o *osDepGraphWorkflow) Entrypoint(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
	return depGraphEntrypoint(
		o, []string{"test", "--print-graph", "--json"},
		invocation, input,
	)
}

// LegacyCliJsonError is the error type returned by the legacy cli
type LegacyCliJsonError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
}

// Error returns the LegacyCliJsonError error message
func (e *LegacyCliJsonError) Error() string {
	return e.ErrorMsg
}

// extractLegacyCLIError extracts the error message from the legacy cli if possible
func extractLegacyCLIError(input error, data []workflow.Data) (output error) {
	output = input

	// extract error from legacy cli if possible and wrap it in an error instance
	_, isExitError := input.(*exec.ExitError)
	if isExitError && data != nil && len(data) > 0 {
		bytes := data[0].GetPayload().([]byte)

		var decodedError LegacyCliJsonError
		err := json.Unmarshal(bytes, &decodedError)
		if err == nil {
			output = &decodedError
		}

	}

	return output
}

func depGraphEntrypoint(
	d workflow.WorkflowRegisterer,
	cmdArgs []string,
	invocation workflow.InvocationContext,
	input []workflow.Data,
) (depGraphList []workflow.Data, err error) {
	debugLogger := d.Logger(invocation)
	debugLogger.Printf("start")

	config := invocation.GetConfiguration()
	for _, flag := range d.GetFlags() {
		if arg, ok := flag.AsArgument(config); ok {
			cmdArgs = append(cmdArgs, arg)
		}
	}

	// This is the directory for OS, or the container name for container. It's not a flag, but a
	// positional argument.
	cmdArgs = append(cmdArgs, config.GetString("targetDirectory"))
	debugLogger.Printf("cli invocation args: %v", cmdArgs)

	config.Set(configuration.RAW_CMD_ARGS, cmdArgs)
	data, err := invocation.GetEngine().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	if err != nil {
		return nil, extractLegacyCLIError(err, data)
	}

	depGraphList, err = extractDepGraphsFromCLIOutput(data[0].GetPayload().([]byte))
	if err != nil {
		return nil, fmt.Errorf("could not extract depGraphs from CLI output: %w", err)
	}

	debugLogger.Printf("done (%d)", len(depGraphList))

	return depGraphList, nil
}

// depGraphSeparator separates the depgraph from the target name and the rest.
// The DepGraph and the name are caught in a capturing group.
//
// The `(?s)` at the beginning enables multiline-matching.
var depGraphSeparator = regexp.MustCompile(`(?s)DepGraph data:(.*?)DepGraph target:(.*?)DepGraph end`)

func extractDepGraphsFromCLIOutput(output []byte) ([]workflow.Data, error) {
	if len(output) == 0 {
		return nil, fmt.Errorf("no dependency graphs found")
	}

	var depGraphs []workflow.Data
	for _, match := range depGraphSeparator.FindAllSubmatch(output, -1) {
		if len(match) != 3 {
			return nil, fmt.Errorf("malformed CLI output, got %v matches", len(match))
		}

		data := workflow.NewData(DATATYPEID_DEPGRAPH, "application/json", match[1])
		data.SetMetaData("Content-Location", strings.TrimSpace(string(match[2])))
		depGraphs = append(depGraphs, data)
	}

	return depGraphs, nil
}
