package configuration

const (
	API_URL                        string = "snyk_api"                      // AKA "endpoint" in the config file
	AUTHENTICATION_SUBDOMAINS      string = "internal_auth_subdomain"       // array of additional subdomains to add authentication for
	AUTHENTICATION_ADDITIONAL_URLS string = "internal_additional_auth_urls" // array of additional urls to add authentication for
	AUTHENTICATION_TOKEN           string = "snyk_token"
	//nolint:gosec // not a token value, a configuration key
	AUTHENTICATION_BEARER_TOKEN     string = "snyk_oauth_token"
	INTEGRATION_NAME                string = "snyk_integration_name"
	INTEGRATION_VERSION             string = "snyk_integration_version"
	INTEGRATION_ENVIRONMENT         string = "snyk_integration_environment"
	INTEGRATION_ENVIRONMENT_VERSION string = "snyk_integration_environment_version"
	ANALYTICS_DISABLED              string = "snyk_disable_analytics"
	ORGANIZATION                    string = "org"
	ORGANIZATION_SLUG               string = "internal_org_slug"
	DEBUG                           string = "debug"
	DEBUG_FORMAT                    string = "debug_format"
	INSECURE_HTTPS                  string = "insecure"
	PROXY_AUTHENTICATION_MECHANISM  string = "proxy_auth"
	CACHE_PATH                      string = "snyk_cache_path"
	WORKFLOW_USE_STDIO              string = "internal_wflstdio"
	RAW_CMD_ARGS                    string = "internal_raw_cmd_args"
	WEB_APP_URL                     string = "internal_snyk_app"
	INPUT_DIRECTORY                 string = "targetDirectory"
	ADD_TRUSTED_CA_FILE             string = "internal_additional_trusted_ca_file" // pem file location containing additional CAs to trust
	FIPS_ENABLED                    string = "gofips"
	WORKING_DIRECTORY               string = "internal_working_dir"
	IS_FEDRAMP                      string = "internal_is_fedramp"
	UNKNOWN_ARGS                    string = "internal_unknown_arguments" // arguments unknown to the current application but maybe relevant for delegated application calls
	TIMEOUT                         string = "snyk_timeout_secs"

	// feature flags
	FF_OAUTH_AUTH_FLOW_ENABLED string = "internal_snyk_oauth_enabled"
	FF_CODE_CONSISTENT_IGNORES string = "internal_snyk_code_ignores_enabled"

	// flags
	FLAG_EXPERIMENTAL       string = "experimental"
	FLAG_INCLUDE_IGNORES    string = "include-ignores"
	FLAG_SEVERITY_THRESHOLD string = "severity-threshold"
)
