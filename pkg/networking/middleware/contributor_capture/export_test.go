package contributor_capture

// Exported for tests in the external contributor_capture_test package.
var (
	ReadRequestBodyForParse = readRequestBodyForParse
	ReadResponseBody        = readResponseBody
	ErrBodyTooLarge         = errBodyTooLarge

	ClassifyEndpoint = classifyEndpoint

	DecodeCaptureBody = decodeCaptureBody

	ParseMonitorProjectID        = parseMonitorProjectID
	ParseCreateTestPublishReport = parseCreateTestPublishReport
	ParseCreateTestID            = parseCreateTestID
	ParseComponentsProjectID     = parseComponentsProjectID
	ParseIaCShareProjectIDs      = parseIaCShareProjectIDs
	ParseAIBomUploadRevisionID   = parseAIBomUploadRevisionID
	ParseDeeproxyReportProjectID = parseDeeproxyReportProjectID
	ProjectIDFromMonitorURI      = projectIDFromMonitorURI
)
