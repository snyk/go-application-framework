package configuration

const (
	ORGANIZATION                   string = "org"
	DEBUG                          string = "debug"
	DEBUG_FORMAT                   string = "debug_format"
	INSECURE_HTTPS                 string = "insecure"
	PROXY_AUTHENTICATION_MECHANISM string = "proxy_auth"
	INPUT_DIRECTORY                string = "targetDirectory"
	FIPS_ENABLED                   string = "gofips"

	// flags
	FLAG_EXPERIMENTAL       string = "experimental"
	FLAG_INCLUDE_IGNORES    string = "include-ignores"
	FLAG_SEVERITY_THRESHOLD string = "severity-threshold"

	// snyk_ constants
	API_URL              string = "snyk_api" // AKA "endpoint" in the config file
	AUTHENTICATION_TOKEN string = "snyk_token"
	//nolint:gosec // not a token value, a configuration key
	AUTHENTICATION_BEARER_TOKEN     string = "snyk_oauth_token"
	INTEGRATION_NAME                string = "snyk_integration_name"
	INTEGRATION_VERSION             string = "snyk_integration_version"
	INTEGRATION_ENVIRONMENT         string = "snyk_integration_environment"
	INTEGRATION_ENVIRONMENT_VERSION string = "snyk_integration_environment_version"
	ANALYTICS_DISABLED              string = "snyk_disable_analytics"
	TEMP_DIR_PATH                   string = "snyk_tmp_path"
	CACHE_PATH                      string = "snyk_cache_path"
	TIMEOUT                         string = "snyk_timeout_secs"
	LOG_LEVEL                       string = "snyk_log_level" // string that defines the log level based on zerolog levels (trace,debug,info,...)

	// internal constants
	CUSTOM_CONFIG_FILES            string = "internal_custom_config_files"
	WORKFLOW_USE_STDIO             string = "internal_wflstdio"
	RAW_CMD_ARGS                   string = "internal_raw_cmd_args"
	WEB_APP_URL                    string = "internal_snyk_app"
	MAX_THREADS                    string = "internal_max_thread_count"
	WORKING_DIRECTORY              string = "internal_working_dir"
	IS_FEDRAMP                     string = "internal_is_fedramp"
	ORGANIZATION_SLUG              string = "internal_org_slug"
	SAST_SETTINGS                  string = "internal_sast_settings"
	AUTHENTICATION_SUBDOMAINS      string = "internal_auth_subdomain"             // array of additional subdomains to add authentication for
	AUTHENTICATION_ADDITIONAL_URLS string = "internal_additional_auth_urls"       // array of additional urls to add authentication for
	ADD_TRUSTED_CA_FILE            string = "internal_additional_trusted_ca_file" // pem file location containing additional CAs to trust
	PREVIEW_FEATURES_ENABLED       string = "internal_preview_features_enabled"   // boolean indicates if preview features shall be enabled
	UNKNOWN_ARGS                   string = "internal_unknown_arguments"          // arguments unknown to the current application but maybe relevant for delegated application calls
	IN_MEMORY_THRESHOLD_BYTES      string = "internal_in_memory_threshold_bytes"  // threshold to determine where to store workflow.Data
	// feature flags
	FF_OAUTH_AUTH_FLOW_ENABLED        string = "internal_snyk_oauth_enabled"
	FF_CODE_CONSISTENT_IGNORES        string = "internal_snyk_code_ignores_enabled"
	FF_CODE_CONSISTENT_REPORT_ENABLED string = "internal_snyk_code_ignores_report_enabled"
	FF_TRANSFORMATION_WORKFLOW        string = "internal_snyk_transformation_workflow_enabled"
)
