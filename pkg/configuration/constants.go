package configuration

const (
	API_URL                        string = "snyk_api"                // AKA "endpoint" in the config file
	AUTHENTICATION_SUBDOMAINS      string = "internal_auth_subdomain" // array of additional subdomains to add authentication for
	AUTHENTICATION_TOKEN           string = "token"
	AUTHENTICATION_BEARER_TOKEN    string = "bearer_token"
	INTEGRATION_NAME               string = "snyk_integration_name"
	INTEGRATION_VERSION            string = "snyk_integration_version"
	ANALYTICS_DISABLED             string = "snyk_disable_analytics"
	ORGANIZATION                   string = "org"
	DEBUG                          string = "debug"
	DEBUG_FORMAT                   string = "debug_format"
	INSECURE_HTTPS                 string = "insecure"
	PROXY_AUTHENTICATION_MECHANISM string = "proxy_auth"
	CACHE_PATH                     string = "snyk_cache_path"
	WORKFLOW_USE_STDIO             string = "wflstdio"
	RAW_CMD_ARGS                   string = "raw_cmd_args"
	WEB_APP_URL                    string = "internal_snyk_app"
	INPUT_DIRECTORY                string = "targetDirectory"
	ADD_TRUSTED_CA_FILE            string = "internal_additional_trusted_ca_file" // pem file location containing additional CAs to trust

	// feature flags
	FF_OAUTH_AUTH_FLOW_ENABLED string = "internal_snyk_oauth_enabled"
)
