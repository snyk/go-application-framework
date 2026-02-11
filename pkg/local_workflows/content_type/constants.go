package content_type

const (
	TEST_SUMMARY         = "application/json; schema=test-summary"
	LOCAL_FINDING_MODEL  = "application/json; schema=local-finding-summary"
	LegacyCLIContentType = "application/json; schema=legacy-cli"
	SARIF_JSON           = "application/sarif+json"
	UFM_RESULT           = "application/ufm.result"
	// LEGACY_CLI_STDOUT is the content type for workflow.Data carrying legacy CLI stdout
	// (e.g. snyk test --json). Payload is []byte (JSON or text). Used so consumers can
	// detect legacy CLI output explicitly instead of "not UFM".
	LEGACY_CLI_STDOUT = "application/legacy-cli.stdout"
)
