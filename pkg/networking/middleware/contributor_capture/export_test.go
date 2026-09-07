package contributor_capture

// Exported for tests in the external contributor_capture_test package.
var (
	PeekRequestBody  = peekRequestBody
	PeekResponseBody = peekResponseBody

	ClassifyEndpoint = classifyEndpoint

	ParseMonitorProjectID        = parseMonitorProjectID
	ParseCreateTestPublishReport = parseCreateTestPublishReport
	ParseCreateTestID            = parseCreateTestID
	ParseComponentsProjectID     = parseComponentsProjectID
	ParseIaCShareProjectIDs      = parseIaCShareProjectIDs
	ParseAIBomUploadRevisionID   = parseAIBomUploadRevisionID
	ParseDeeproxyReportProjectID = parseDeeproxyReportProjectID
	ProjectIDFromMonitorURI      = projectIDFromMonitorURI
)

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
