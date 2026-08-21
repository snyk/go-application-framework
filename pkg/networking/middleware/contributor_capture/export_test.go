package contributor_capture

// Exported for tests in the external contributor_capture_test package.
var (
	ReadRequestBody  = readRequestBody
	ReadResponseBody = readResponseBody
	ErrBodyTooLarge  = errBodyTooLarge

	ClassifyEndpoint = classifyEndpoint

	ParseCreateTestPublishReport = parseCreateTestPublishReport
	ParseCreateTestID            = parseCreateTestID
	ParseMonitorProjectID        = parseMonitorProjectID
	ParseIaCShareProjectIDs      = parseIaCShareProjectIDs
	ParseComponentsProjectID     = parseComponentsProjectID
	ParseAIBomUploadRevisionID   = parseAIBomUploadRevisionID
)

// ResetPendingTests clears the package-level pending-test state.
func ResetPendingTests() {
	pendingTestsSingleton.mu.Lock()
	defer pendingTestsSingleton.mu.Unlock()
	pendingTestsSingleton.ids = make(map[string]struct{})
}
