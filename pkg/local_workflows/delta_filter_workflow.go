package localworkflows

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/utils/findings"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	DeltaFilterFindingsWorkflowName = "findings.filter.delta"
)

var WORKFLOWID_FILTER_FINDINGS_DELTA = workflow.NewWorkflowIdentifier(DeltaFilterFindingsWorkflowName)

// InitDeltaFilterFindingsWorkflow registers the delta filter workflow with the engine.
func InitDeltaFilterFindingsWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(DeltaFilterFindingsWorkflowName, pflag.ExitOnError)
	flags.String(configuration.FLAG_CHANGED_LINES_FILE, "", "Path to JSON file describing changed line ranges for delta filtering")
	flags.String(configuration.FLAG_CHANGED_LINES, "", "Inline JSON describing changed line ranges for delta filtering")
	_, err := engine.Register(WORKFLOWID_FILTER_FINDINGS_DELTA, workflow.ConfigurationOptionsFromFlagset(flags), deltaFilterFindingsEntryPoint)
	return err
}

// filteredTestResult wraps a testapi.TestResult and returns only delta-filtered findings.
type filteredTestResult struct {
	testapi.TestResult
	filtered []testapi.FindingData
	complete bool
}

func (f *filteredTestResult) Findings(_ context.Context) ([]testapi.FindingData, bool, error) {
	return f.filtered, f.complete, nil
}

func deltaFilterFindingsEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	scopeData, err := resolveChangedLinesInput(config)
	if err != nil {
		return nil, err
	}
	if scopeData == nil {
		logger.Println("Delta filter: no changed-lines input, passing through")
		return input, nil
	}

	scope, err := findings.ParseChangedScope(scopeData)
	if err != nil {
		return nil, snyk_errors.Error{
			Title:          "Invalid changed-lines input",
			Classification: "ActionableByUser",
			Level:          "error",
			Detail:         fmt.Sprintf("changed-lines input is malformed: %s", err.Error()),
		}
	}

	output := make([]workflow.Data, 0, len(input))
	for _, data := range input {
		mimeType := data.GetContentType()
		switch {
		case strings.HasPrefix(mimeType, content_type.LOCAL_FINDING_MODEL):
			filtered, filterErr := applyDeltaToLocalFindings(data, scope, logger)
			if filterErr != nil {
				logger.Warn().Err(filterErr).Msg("Delta filter: failed to filter LOCAL_FINDING_MODEL, passing through")
				output = append(output, data)
				continue
			}
			output = append(output, filtered)

		case strings.HasPrefix(mimeType, content_type.UFM_RESULT):
			filtered, filterErr := applyDeltaToUFMResult(data, scope, logger)
			if filterErr != nil {
				logger.Warn().Err(filterErr).Msg("Delta filter: failed to filter UFM_RESULT, passing through")
				output = append(output, data)
				continue
			}
			output = append(output, filtered)

		default:
			output = append(output, data)
		}
	}
	return output, nil
}

// resolveChangedLinesInput reads raw JSON bytes from --changed-lines-file or --changed-lines.
// Returns nil if neither flag is set (no-op pass-through).
func resolveChangedLinesInput(config configuration.Configuration) ([]byte, error) {
	if filePath := config.GetString(configuration.FLAG_CHANGED_LINES_FILE); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, snyk_errors.Error{
				Title:          "Cannot read changed-lines file",
				Classification: "ActionableByUser",
				Level:          "error",
				Detail:         fmt.Sprintf("--changed-lines-file %q: %s", filePath, err.Error()),
			}
		}
		return data, nil
	}
	if inline := config.GetString(configuration.FLAG_CHANGED_LINES); inline != "" {
		return []byte(inline), nil
	}
	return nil, nil
}

func applyDeltaToLocalFindings(data workflow.Data, scope findings.ChangedScope, logger *zerolog.Logger) (workflow.Data, error) {
	payload, ok := data.GetPayload().([]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected payload type %T", data.GetPayload())
	}

	var findingsModel local_models.LocalFinding
	if err := json.Unmarshal(payload, &findingsModel); err != nil {
		return nil, fmt.Errorf("unmarshal LOCAL_FINDING_MODEL: %w", err)
	}

	before := len(findingsModel.Findings)
	filter := findings.GetDeltaFilter(scope)
	applyFilters(&findingsModel, []findings.FindingsFilterFunc{filter})
	local_models.UpdateFindingSummary(&findingsModel)
	logger.Debug().Msgf("Delta filter: LOCAL_FINDING_MODEL %d -> %d findings", before, len(findingsModel.Findings))

	filtered, err := json.Marshal(findingsModel)
	if err != nil {
		return nil, fmt.Errorf("marshal filtered findings: %w", err)
	}

	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS_DELTA, DeltaFilterFindingsWorkflowName),
		content_type.LOCAL_FINDING_MODEL,
		filtered,
		workflow.WithInputData(data),
	), nil
}

func applyDeltaToUFMResult(data workflow.Data, scope findings.ChangedScope, logger *zerolog.Logger) (workflow.Data, error) {
	results := ufm.GetTestResultsFromWorkflowData(data)
	if results == nil {
		return data, nil
	}

	ctx := context.Background()
	filteredResults := make([]testapi.TestResult, 0, len(results))
	for _, result := range results {
		findingsList, complete, err := result.Findings(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetch UFM findings: %w", err)
		}

		var kept []testapi.FindingData
		for _, f := range findingsList {
			if ufmFindingInDeltaScope(f, scope) {
				kept = append(kept, f)
			}
		}
		logger.Debug().Msgf("Delta filter: UFM_RESULT %d -> %d findings", len(findingsList), len(kept))

		filteredResults = append(filteredResults, &filteredTestResult{
			TestResult: result,
			filtered:   kept,
			complete:   complete,
		})
	}

	newData := ufm.CreateWorkflowDataFromTestResults(WORKFLOWID_FILTER_FINDINGS_DELTA, filteredResults)
	if newData == nil {
		// All results empty after filtering — return minimal valid UFM_RESULT
		return workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS_DELTA, DeltaFilterFindingsWorkflowName),
			content_type.UFM_RESULT,
			[]byte("[]"),
			workflow.WithInputData(data),
		), nil
	}
	return newData, nil
}

// ufmFindingInDeltaScope returns true if any source location in the UFM finding
// intersects the changed scope.
func ufmFindingInDeltaScope(finding testapi.FindingData, scope findings.ChangedScope) bool {
	if finding.Attributes == nil || len(finding.Attributes.Locations) == 0 {
		return false
	}
	for _, loc := range finding.Attributes.Locations {
		sl, err := loc.AsSourceLocation()
		if err != nil {
			continue
		}
		normPath := findings.NormalizeRelPath(sl.FilePath)
		if !scope.FileInScope(normPath) {
			continue
		}
		// file in scope, no line data — keep
		if sl.FromLine == 0 && (sl.ToLine == nil || *sl.ToLine == 0) {
			return true
		}
		end := sl.FromLine
		if sl.ToLine != nil && *sl.ToLine > 0 {
			end = *sl.ToLine
		}
		if scope.Intersects(normPath, sl.FromLine, end) {
			return true
		}
	}
	return false
}
