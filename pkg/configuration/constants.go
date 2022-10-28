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
	INSECURE_HTTPS                 string = "insecure"
	PROXY_AUTHENTICATION_MECHANISM string = "proxy_auth"
	CACHE_PATH                     string = "snyk_cache_path"
	WORKFLOW_USE_STDIO             string = "wflstdio"
)

const SNYK_DEFAULT_API_URL = "https://api.snyk.io"
