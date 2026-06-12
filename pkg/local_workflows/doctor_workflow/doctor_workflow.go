// Package doctor_workflow implements the `snyk doctor` spike (CLI-1570):
// read a debug log (STDIN or --input), gather auth and connectivity context
// via the existing whoami and connectivity-check workflows, consolidate
// everything into one report, and — when an LLM model is configured — run a
// first-pass diagnosis.
package doctor_workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	connectivity_check "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"
	"github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension/connectivity"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/bundle"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/llm"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/logscan"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	doctorWorkflowName = "doctor"

	inputFlag         = "input"
	includeReportFlag = "include-report"

	// LLM configuration; resolvable from environment variables of the same
	// name. The model is the opt-in switch: without it, doctor produces the
	// consolidated report only.
	configLLMProvider = "SNYK_DOCTOR_LLM_PROVIDER"
	configLLMBaseURL  = "SNYK_DOCTOR_LLM_BASE_URL"
	configLLMModel    = "SNYK_DOCTOR_LLM_MODEL"

	// generous because local models on modest hardware are slow
	llmTimeout = 5 * time.Minute
)

var WORKFLOWID_DOCTOR workflow.Identifier = workflow.NewWorkflowIdentifier(doctorWorkflowName)

// whoami lives in the parent localworkflows package, which cannot be
// imported from here without a cycle; reconstruct its identifier instead.
var workflowIDWhoAmI workflow.Identifier = workflow.NewWorkflowIdentifier("whoami")

func InitDoctorWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(doctorWorkflowName, pflag.ExitOnError)
	flags.String(inputFlag, "", "path to a Snyk CLI debug log file (defaults to STDIN)")
	flags.Bool(includeReportFlag, false, "print the full diagnostic report alongside the LLM diagnosis")

	_, err := engine.Register(WORKFLOWID_DOCTOR, workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(flags)), doctorEntryPoint)
	return err
}

func doctorEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	console := invocationCtx.GetUserInterface()
	spinner := console.NewProgressBar()
	// each phase gets a fresh spinner: Clear() retires a bar for good, and
	// the connectivity check drives its own progress bar in between
	checkup := func(title string) {
		_ = spinner.Clear()
		spinner = console.NewProgressBar()
		spinner.SetTitle(title)
		_ = spinner.UpdateProgress(ui.InfiniteProgress)
	}
	restSpinner := func() { _ = spinner.Clear() }
	defer restSpinner()

	checkup("Reading your chart (parsing the debug log)")
	debugLog, err := readDebugLog(config.GetString(inputFlag))
	if err != nil {
		return nil, err
	}
	logger.Debug().Msgf("doctor: read %d bytes of debug log", len(debugLog))

	scanResult := logscan.Scan(debugLog)

	checkup("Taking your pulse (authentication check)")
	whoAmI := gatherWhoAmI(invocationCtx)

	// the connectivity check renders its own progress bar; stand aside
	restSpinner()
	connectivity := gatherConnectivity(invocationCtx)

	diagnosticBundle := &bundle.DiagnosticBundle{
		Header:       logscan.StripLinePrefixes(scanResult.Header),
		Footer:       logscan.StripLinePrefixes(scanResult.Footer),
		Events:       toBundleEvents(scanResult.NotableEvents),
		WhoAmI:       whoAmI,
		Connectivity: connectivity,
	}

	// lipgloss keeps one global color profile and auto-detection often
	// lands on Ascii in this context; set it explicitly AFTER all invoked
	// workflows ran, because the connectivity formatter sets it globally too
	color := useColor(config)
	if color {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	var output string
	if model := config.GetString(configLLMModel); model == "" {
		logger.Debug().Msgf("doctor: %s not set, skipping LLM diagnosis", configLLMModel)
		st := bundle.NewStyles(color)
		output = diagnosticBundle.Render(color) +
			"\n" + st.Dim(fmt.Sprintf("Tip: set %s to also get an automated diagnosis with remediation advice.", configLLMModel)) + "\n"
	} else {
		// diagnosis mode: the terminal gets the live-checks digest and the
		// diagnosis; the full report is the LLM input, and printed only on
		// --include-report
		checkup(fmt.Sprintf("Consulting the specialist (%s, this can take a minute)", model))
		diagnosis, diagErr := diagnose(invocationCtx, llmInput(diagnosticBundle), model)
		if config.GetBool(includeReportFlag) {
			output = diagnosticBundle.Render(color) + renderDiagnosis(diagnosis, diagErr, color)
		} else {
			st := bundle.NewStyles(color)
			output = diagnosticBundle.RenderLiveChecks(color) + renderDiagnosis(diagnosis, diagErr, color) +
				"\n" + st.Dim(fmt.Sprintf("Add --%s to also print the full diagnostic report for support tickets.", includeReportFlag)) + "\n"
		}
	}
	restSpinner()

	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DOCTOR, doctorWorkflowName),
		"text/plain",
		[]byte(output),
		workflow.WithLogger(logger),
		workflow.WithConfiguration(config),
	)
	return []workflow.Data{outputData}, nil
}

func useColor(config configuration.Configuration) bool {
	return !config.GetBool("no-color") && term.IsTerminal(int(os.Stdout.Fd()))
}

func readDebugLog(inputPath string) (string, error) {
	if inputPath != "" {
		content, err := os.ReadFile(inputPath)
		if err != nil {
			return "", fmt.Errorf("failed to read debug log from %s: %w", inputPath, err)
		}
		return string(content), nil
	}

	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no debug log provided: pipe one in (snyk test -d 2>&1 | snyk doctor) or use --input <file>")
	}
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read debug log from STDIN: %w", err)
	}
	return string(content), nil
}

func toBundleEvents(events []logscan.NotableEvent) []bundle.Event {
	result := make([]bundle.Event, 0, len(events))
	for _, e := range events {
		result = append(result, bundle.Event{Line: e.Line, Kind: string(e.Kind), Message: e.Message})
	}
	return result
}

func gatherWhoAmI(invocationCtx workflow.InvocationContext) bundle.Signal {
	config := invocationCtx.GetConfiguration().Clone()

	data, err := invocationCtx.GetEngine().InvokeWithConfig(workflowIDWhoAmI, config)
	if err != nil {
		return bundle.Signal{Status: bundle.SignalFailed, Summary: "not authenticated", Detail: err.Error()}
	}
	user, ok := firstPayloadString(data)
	if !ok {
		return bundle.Signal{Status: bundle.SignalFailed, Summary: "whoami returned no usable result"}
	}
	return bundle.Signal{Status: bundle.SignalOK, Summary: strings.TrimSpace(user)}
}

// connectivityResult mirrors connectivity.ConnectivityCheckResult, narrowed
// to the fields doctor presents; the original's `error`-typed fields cannot
// be round-tripped through encoding/json.
type connectivityResult struct {
	ProxyConfig connectivity.ProxyConfig `json:"proxyConfig"`
	HostResults []struct {
		Host    string                        `json:"host"`
		Status  connectivity.ConnectionStatus `json:"status"`
		Message string                        `json:"message"`
	} `json:"hostResults"`
	TODOs         []connectivity.TODO         `json:"todos"`
	Organizations []connectivity.Organization `json:"organizations"`
	TokenPresent  bool                        `json:"tokenPresent"`
}

func gatherConnectivity(invocationCtx workflow.InvocationContext) bundle.ConnectivitySummary {
	config := invocationCtx.GetConfiguration().Clone()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	config.Set("json", true)
	// invoked configs don't inherit the target workflow's flag defaults
	config.Set("timeout", 10)
	config.Set("max-org-count", 100)

	data, err := invocationCtx.GetEngine().InvokeWithConfig(connectivity_check.WORKFLOWID_CONNECTIVITY_CHECK, config)
	if err != nil {
		return bundle.ConnectivitySummary{Failed: true, FailureText: err.Error()}
	}
	payload, ok := firstPayloadString(data)
	if !ok {
		return bundle.ConnectivitySummary{Failed: true, FailureText: "connectivity check returned no usable result"}
	}

	var result connectivityResult
	if unmarshalErr := json.Unmarshal([]byte(payload), &result); unmarshalErr != nil {
		return bundle.ConnectivitySummary{Failed: true, FailureText: fmt.Sprintf("could not decode connectivity result: %s", unmarshalErr)}
	}
	return summarizeConnectivity(result)
}

// quotedTokenRe matches 'host' / "url" tokens, the only part that differs
// between the per-host warnings the connectivity check emits.
var quotedTokenRe = regexp.MustCompile(`'[^']*'|"[^"]*"`)

// describeOrganizations turns the org list into display lines, default org
// first, capped to keep the report skimmable.
func describeOrganizations(orgs []connectivity.Organization, limit int) []string {
	var lines []string
	for _, org := range orgs {
		line := org.Slug
		if org.IsDefault {
			line += " (default)"
			lines = append([]string{line}, lines...)
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) > limit {
		hidden := len(lines) - limit
		lines = append(lines[:limit], fmt.Sprintf("+%d more", hidden))
	}
	return lines
}

func summarizeConnectivity(result connectivityResult) bundle.ConnectivitySummary {
	summary := bundle.ConnectivitySummary{
		Proxy:        "none detected",
		HostsTotal:   len(result.HostResults),
		TokenPresent: result.TokenPresent,
		OrgCount:     len(result.Organizations),
	}

	if result.ProxyConfig.Detected {
		summary.Proxy = fmt.Sprintf("%s=%s", result.ProxyConfig.Variable, result.ProxyConfig.URL)
		if result.ProxyConfig.NoProxy != "" {
			summary.Proxy += fmt.Sprintf("  (NO_PROXY=%s)", result.ProxyConfig.NoProxy)
		}
	}

	failureIndex := map[string]int{}
	for _, host := range result.HostResults {
		switch host.Status {
		case connectivity.StatusOK, connectivity.StatusReachable, connectivity.StatusProxyAuthSupported:
			summary.HostsOK++
		default:
			status := host.Status.String()
			i, ok := failureIndex[status]
			if !ok {
				summary.FailureGroups = append(summary.FailureGroups, bundle.HostFailureGroup{Status: status})
				i = len(summary.FailureGroups) - 1
				failureIndex[status] = i
			}
			summary.FailureGroups[i].Hosts = append(summary.FailureGroups[i].Hosts, host.Host)
		}
	}

	summary.Organizations = describeOrganizations(result.Organizations, 10)

	warningIndex := map[string]int{}
	for _, todo := range result.TODOs {
		if todo.Level == connectivity.TodoInfo {
			continue
		}
		key := quotedTokenRe.ReplaceAllString(todo.Message, "*")
		if i, ok := warningIndex[key]; ok {
			summary.Warnings[i].Similar++
			continue
		}
		summary.Warnings = append(summary.Warnings, bundle.Warning{Message: todo.Message})
		warningIndex[key] = len(summary.Warnings) - 1
	}
	return summary
}

func firstPayloadString(data []workflow.Data) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	switch payload := data[0].GetPayload().(type) {
	case []byte:
		return string(payload), true
	case string:
		return payload, true
	default:
		return "", false
	}
}

// llmInput is the full report plus the deterministic cross-referenced
// signals; the signals anchor the model so it doesn't hedge across causes
// the evidence already rules out.
func llmInput(diagnosticBundle *bundle.DiagnosticBundle) string {
	input := diagnosticBundle.Render(false)
	observations := diagnosticBundle.Observations()
	if len(observations) == 0 {
		return input
	}
	input += "\n\nKey Signals (precomputed by snyk doctor, treat as ground truth)\n"
	for _, observation := range observations {
		input += "\n - " + observation
	}
	return input
}

func diagnose(invocationCtx workflow.InvocationContext, report, model string) (llm.Diagnosis, error) {
	config := invocationCtx.GetConfiguration()

	provider, err := llm.NewProvider(llm.Options{
		Provider: config.GetString(configLLMProvider),
		BaseURL:  config.GetString(configLLMBaseURL),
		Model:    model,
	})
	if err != nil {
		return llm.Diagnosis{}, err
	}

	parentCtx := invocationCtx.Context()
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, llmTimeout)
	defer cancel()

	return provider.Diagnose(ctx, report)
}
