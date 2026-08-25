package contributor_capture

// Exported for tests in the external contributor_capture_test package.
var (
	ReadRequestBodyForParse = readRequestBodyForParse
	ReadResponseBody        = readResponseBody
	ErrBodyTooLarge         = errBodyTooLarge

	ClassifyEndpoint = classifyEndpoint

	ParseCreateTestPublishReport = parseCreateTestPublishReport
	ParseCreateTestID            = parseCreateTestID
	ParseMonitorProjectID        = parseMonitorProjectID
	ParseIaCShareProjectIDs      = parseIaCShareProjectIDs
	ParseComponentsProjectID     = parseComponentsProjectID
	ParseAIBomUploadRevisionID   = parseAIBomUploadRevisionID
	ParseDeeproxyReportProjectID = parseDeeproxyReportProjectID
	DecodeCaptureBody            = decodeCaptureBody
)
