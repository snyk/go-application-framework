package configuration

const (
	// ---------
	// platform related configuration that is normally not required to be accessed directly
	// ---------

	DEBUG                          string = "debug"                               // DEBUG (boolean) sets/returns if debugging is enabled or not
	LOG_LEVEL                      string = "snyk_log_level"                      // LOG_LEVEL (string) return the log level based on zerolog levels (trace,debug,info,...)
	INSECURE_HTTPS                 string = "insecure"                            // INSECURE_HTTPS (boolean) sets/returns if the network stack shall verify the certificate chain when making HTTPS requests
	ADD_TRUSTED_CA_FILE            string = "internal_additional_trusted_ca_file" // ADD_TRUSTED_CA_FILE (string) pem file location containing additional CAs to trust
	PROXY_AUTHENTICATION_MECHANISM string = "proxy_auth"                          // PROXY_AUTHENTICATION_MECHANISM (httpauth.AuthenticationMechanism) sets/returns the proxy authentication mechanism
	MAX_THREADS                    string = "internal_max_thread_count"           // MAX_THREADS (int) sets/returns the maximum number of threads that can be used by Extensions
	CONFIG_CACHE_TTL               string = "internal_config_cache_ttl"           // CONFIG_CACHE_TTL (int) sets/returns the time to live for values cached by the configuration
	CONFIG_CACHE_DISABLED          string = "internal_config_cache_disabled"      // CONFIG_CACHE_DISABLED (boolean) sets/returns if the configuration cache is disabled or not
	ANALYTICS_DISABLED             string = "snyk_disable_analytics"              // ANALYTICS_DISABLED (boolean) sets/returns if analytics shall be disabled or not
	TIMEOUT                        string = "snyk_timeout_secs"                   // TIMEOUT (int) sets/returns the timeout in seconds for the application execution
	IN_MEMORY_THRESHOLD_BYTES      string = "internal_in_memory_threshold_bytes"  // IN_MEMORY_THRESHOLD_BYTES (int) threshold to determine if workflow.Data should be stored in memory or on disk
	IS_FEDRAMP                     string = "internal_is_fedramp"                 // IS_FEDRAMP (boolean) returns if the application is running in a FedRAMP environment or not
	FIPS_ENABLED                   string = "gofips"                              // FIPS_ENABLED (boolean) returns if FIPS mode is enabled or not

	// ---------
	// environment information available via the configuration
	// ---------

	INTEGRATION_NAME                string = "snyk_integration_name"                // INTEGRATION_NAME (string) sets/returns the name of the integration for example the name of an IDE plugin
	INTEGRATION_VERSION             string = "snyk_integration_version"             // INTEGRATION_VERSION (string) sets/returns the version of the integration for example the version of an IDE plugin
	INTEGRATION_ENVIRONMENT         string = "snyk_integration_environment"         // INTEGRATION_ENVIRONMENT (string) sets/returns the environment of the integration for example the IDE name
	INTEGRATION_ENVIRONMENT_VERSION string = "snyk_integration_environment_version" // INTEGRATION_ENVIRONMENT_VERSION (string) sets/returns the version of the environment of the integration for example the IDE version

	// ---------
	// Org related configuration
	// ---------

	ORGANIZATION      string = "org"               // ORGANIZATION (string) sets/returns the Organization ID
	ORGANIZATION_SLUG string = "internal_org_slug" // ORGANIZATION_SLUG (string) returns the slug of the organization and correlates to the ORGANIZATION ID.

	// ---------
	// URL configuration
	// ---------

	API_URL     string = "snyk_api"          // API_URL (string) sets/returns the API URL, the url returned will always be valid and normalized
	WEB_APP_URL string = "internal_snyk_app" // WEB_APP_URL (string) returns the URL of the web application and is derived from the API_URL

	// ---------
	// authentication related configuration that is normally not required to be accessed directly
	// ---------

	AUTHENTICATION_TOKEN string = "snyk_token" // AUTHENTICATION_TOKEN (string) sets/returns PAT and API tokens (normally this value doesn't have to be used directly)
	//nolint:gosec // not a token value, a configuration key
	AUTHENTICATION_BEARER_TOKEN    string = "snyk_oauth_token"              // AUTHENTICATION_BEARER_TOKEN (string) sets/returns OAuth access tokens  (normally this value doesn't have to be used directly)
	AUTHENTICATION_SUBDOMAINS      string = "internal_auth_subdomain"       // AUTHENTICATION_SUBDOMAINS ([]string) array of additional subdomains to add authentication for
	AUTHENTICATION_ADDITIONAL_URLS string = "internal_additional_auth_urls" // AUTHENTICATION_ADDITIONAL_URLS ([]string) array of additional urls to add authentication for

	// ---------
	// general application configuration
	// ---------

	TEMP_DIR_PATH string = "snyk_tmp_path"   // TEMP_DIR_PATH (string) returns the temporary directory that can be used by Extensions and is valid during the execution of the application. It is guaranteed to be set and existing and match the documented paths
	CACHE_PATH    string = "snyk_cache_path" // CACHE_PATH (string) returns the cache directory that can be used by Extensions and is valid between multiple invocations of the application. It is guaranteed to be set and existing and match the documented paths

	// ---------
	// general workflow configuration
	// ---------

	FLAG_EXPERIMENTAL        string = "experimental"                      // FLAG_EXPERIMENTAL (boolean) returns if experimental features shall be enabled or not, workflows should register this value as a flag to indicate that they might change before being GAed
	PREVIEW_FEATURES_ENABLED string = "internal_preview_features_enabled" // PREVIEW_FEATURES_ENABLED (boolean) indicates if preview features shall be enabled, this can be used to limit features to the preview version only
	FLAG_INCLUDE_IGNORES     string = "include-ignores"                   // FLAG_INCLUDE_IGNORES (boolean) sets/returns if ignores shall be displayed or not
	FLAG_SEVERITY_THRESHOLD  string = "severity-threshold"                // FLAG_SEVERITY_THRESHOLD (string) sets/returns the severity threshold
	FLAG_REMOTE_REPO_URL     string = "remote-repo-url"                   // FLAG_REMOTE_REPO_URL (string) sets/returns the remote repository URL
	INPUT_DIRECTORY          string = "targetDirectory"                   // INPUT_DIRECTORY ([]string) sets/returns the input directories that the application shall process
	CUSTOM_CONFIG_FILES      string = "internal_custom_config_files"
	WORKFLOW_USE_STDIO       string = "internal_wflstdio"
	RAW_CMD_ARGS             string = "internal_raw_cmd_args"
	UNKNOWN_ARGS             string = "internal_unknown_arguments" // UNKNOWN_ARGS ([]string) arguments unknown to the current application but maybe relevant for delegated application calls

	// ---------
	// subprocess environment
	// ---------

	SUBPROCESS_ENVIRONMENT string = "internal_subprocess_environment" // SUBPROCESS_ENVIRONMENT ([]string) environment variables to be passed to subprocesses
	WORKING_DIRECTORY      string = "internal_working_dir"            // WORKING_DIRECTORY (string) working directory to be used by subprocesses

	// ---------
	// feature flags
	// ---------

	FF_OAUTH_AUTH_FLOW_ENABLED string = "internal_snyk_oauth_enabled"
	FF_TRANSFORMATION_WORKFLOW string = "internal_snyk_transformation_workflow_enabled"
	// Feature flag to enable consistent ignores for code ,used in code-client-go's code workflow
	FF_CODE_CONSISTENT_IGNORES string = "internal_snyk_code_ignores_enabled"
	// Feature flag to enable native implementation for code, used in code-client-go's code workflow
	FF_CODE_NATIVE_IMPLEMENTATION string = "internal_snyk_code_native_implementation"
)
