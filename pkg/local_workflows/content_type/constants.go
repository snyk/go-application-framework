package content_type

const (
	TEST_SUMMARY        = "application/json; schema=test-summary"
	LOCAL_FINDING_MODEL = "application/json; schema=local-finding-summary"
	LEGACY_CLI          = "application/json; schema=legacy-cli"
	SARIF_JSON          = "application/sarif+json"
	HTML                = "text/html"
	UFM_RESULT          = "application/ufm.result"
	// MACHINE_ENROLLMENT is a JSON object with the fields client_id, enrolled_machine_id and key_id; the private key is never included.
	MACHINE_ENROLLMENT = "application/json; schema=machine-enrollment"
)
