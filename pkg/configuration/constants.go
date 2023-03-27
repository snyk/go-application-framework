package configuration

const (
	API_URL                        string = "snyk_api"
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
	// feature flags
	FF_OAUTH_AUTH_FLOW_ENABLED string = "internal_snyk_oauth_enabled"
)
