package contributor_capture

import (
	"io"

	"github.com/snyk/go-application-framework/internal/contributors"
)

// Exported for tests in the external contributor_capture_test package.
var (
	ClassifyEndpoint = classifyEndpoint

	ScanResponseBody = scanResponseBody
	ScanRequestBody  = scanRequestBody[string]
	MissReasonFor    = missReasonFor

	ExtractMonitorProjectID        = extractMonitorProjectID
	ExtractIaCShareProjectID       = extractIaCShareProjectID
	ExtractCreateTestID            = extractCreateTestID
	ExtractComponentsProjectID     = extractComponentsProjectID
	ExtractDeeproxyReportProjectID = extractDeeproxyReportProjectID
	ExtractAIBomUploadRevisionID   = extractAIBomUploadRevisionID
	ProjectIDFromMonitorURI        = projectIDFromMonitorURI

	ErrScanBudget = errScanBudget
	ErrScanPanic  = errScanPanic
)

const (
	MaxScanBytes  = maxScanBytes
	MaxDrainBytes = maxDrainBytes
)

// ExtractCreateTestReport flattens the internal result so tests can assert on
// the report flag and whether it was known separately.
func ExtractCreateTestReport(r io.Reader) (report bool, known bool, err error) {
	result, err := extractCreateTestReport(r)
	return result.report, result.known, err
}

// MissReason aliases the reason type so tests need not import the internal
// contributors package for it.
type MissReason = contributors.MissReason

type EndpointKind = endpointKind

const (
	EndpointNone             = endpointNone
	EndpointRegistryMonitor  = endpointRegistryMonitor
	EndpointRegistryIaCShare = endpointRegistryIaCShare
	EndpointTestCreate       = endpointTestCreate
	EndpointTestComponents   = endpointTestComponents
	EndpointAIBomUpload      = endpointAIBomUpload
	EndpointDeeproxyReport   = endpointDeeproxyReport
)
