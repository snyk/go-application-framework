// Package code provides a scanner implementation for Snyk Code
package code

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/product"
	"github.com/snyk/go-application-framework/pkg/types"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var _ types.Scanner = (*Scanner)(nil)
var _ types.IssueProvider = (*Scanner)(nil)
var _ types.CacheProvider = (*Scanner)(nil)

// Scanner implements the types.Scanner interface for Snyk Code
type Scanner struct {
	engine  workflow.Engine
	product product.Product
}

func (s *Scanner) IsProviderFor(issueType product.FilterableIssueType) bool {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) Clear() {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) ClearIssues(path types.FilePath) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) IssuesForFile(path types.FilePath) []types.Issue {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) Issue(key string) types.Issue {
	//TODO implement me
	panic("implement me")
}

func (s *Scanner) Issues() types.IssuesByFile {
	//TODO implement me
	panic("implement me")
}

// New creates a new Scanner instance
func New(engine workflow.Engine) *Scanner {
	return &Scanner{
		engine:  engine,
		product: product.ProductCode,
	}
}

// Scan implements the types.Scanner interface
// It runs the code workflow and processes the results
func (s *Scanner) Scan(ctx context.Context, path types.FilePath, processResults types.ScanResultProcessor, folderPath types.FilePath) {
	// Create a timer to measure scan duration
	start := time.Now()

	// Configure the workflow invocation
	config := s.engine.GetConfiguration().Clone()
	config.Set(configuration.INPUT_DIRECTORY, string(path))

	// Set up scan data with default values
	scanData := types.ScanData{
		Product:           s.product,
		Path:              path,
		IsDeltaScan:       false,
		SendAnalytics:     true,
		UpdateGlobalCache: true,
	}

	// Invoke the code workflow
	results, err := s.engine.InvokeWithConfig(localworkflows.WORKFLOWID_CODE, config)

	// Calculate scan duration
	scanData.DurationMs = time.Since(start)
	scanData.TimestampFinished = time.Now()

	// Handle errors from workflow invocation
	if err != nil {
		scanData.Err = fmt.Errorf("workflow invocation failed: %w", err)
		processResults(ctx, scanData)
		return
	}

	// Check if we have workflow results
	if len(results) == 0 {
		scanData.Err = fmt.Errorf("no results from code workflow")
		processResults(ctx, scanData)
		return
	}

	// Process results data
	for _, data := range results {
		contentType := data.GetContentType()

		switch contentType {
		// Handle findings data from the code workflow
		case "application/vnd.code.finding+json":
			payload := data.GetPayload()
			if payload == nil {
				scanData.Err = fmt.Errorf("nil payload for content type: %s", contentType)
				processResults(ctx, scanData)
				return
			}

			// Parse the payload as a LocalFinding
			localFinding, ok := payload.(local_models.LocalFinding)
			if !ok {
				scanData.Err = fmt.Errorf("unexpected payload type for content type %s", contentType)
				processResults(ctx, scanData)
				return
			}

			// Convert local findings to issues
			issues := ConvertLocalFindingToIssues(&localFinding, string(path))

			// Append the issues to the scan data
			scanData.Issues = append(scanData.Issues, issues...)

		// Handle SARIF data
		case "application/sarif+json":
			// For backward compatibility, handle SARIF directly if needed
			payload := data.GetPayload()
			if payload == nil {
				scanData.Err = fmt.Errorf("nil payload for content type: %s", contentType)
				processResults(ctx, scanData)
				return
			}

			var sarifJson string

			// Handle different payload types
			switch v := payload.(type) {
			case string:
				sarifJson = v
			case []byte:
				sarifJson = string(v)
			default:
				scanData.Err = fmt.Errorf("unexpected payload type for SARIF data: %T", payload)
				continue
			}

			// Log a warning since we should be using findings data
			logger := s.engine.GetLogger()
			// Only use logger if it's available (added for testing)
			if logger != nil && !isNilInterface(logger) {
				logger.Warn().Msg("Using SARIF instead of findings data - converting to LocalFinding model")
			}

			// Try to parse the payload as JSON
			var sarifDoc sarif.SarifDocument
			if err := json.Unmarshal([]byte(sarifJson), &sarifDoc); err != nil {
				scanData.Err = fmt.Errorf("failed to parse SARIF: %w", err)
				processResults(ctx, scanData)
				return
			}

			// Create an empty test summary
			testSummary := &json_schemas.TestSummary{
				Path: string(path),
				Type: "sast",
			}

			// Convert the SARIF document to a LocalFinding
			localFinding, err := local_models.TransformToLocalFindingModelFromSarif(&sarifDoc, testSummary)
			if err != nil {
				scanData.Err = fmt.Errorf("failed to transform SARIF: %w", err)
				processResults(ctx, scanData)
				return
			}

			// Convert LocalFinding to issues
			issues := ConvertLocalFindingToIssues(&localFinding, string(path))

			// Append the issues to the scan data
			scanData.Issues = append(scanData.Issues, issues...)
		}
	}

	// Process the results
	processResults(ctx, scanData)
}

// isNilInterface safely checks if an interface is nil by examining both the interface itself
// and the value it points to, which is necessary for proper nil checking of interface values
func isNilInterface(i interface{}) bool {
	return i == nil || (reflect.ValueOf(i).Kind() == reflect.Ptr && reflect.ValueOf(i).IsNil())
}
