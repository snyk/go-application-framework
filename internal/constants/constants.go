package constants

const SNYK_DEFAULT_API_URL = "https://api.snyk.io"
const SNYK_DEFAULT_API_VERSION = "2024-04-22"
const SNYK_DEFAULT_IN_MEMORY_THRESHOLD_MB = 512 * 1024 * 1024
const SNYK_DOCS_URL = "https://docs.snyk.io"
const SNYK_DOCS_ERROR_CATALOG_PATH = "/scan-with-snyk/error-catalog"

// SNYK_DEFAULT_ALLOWED_HOST_REGEXP is inert, no longer read anywhere in this
// module. It's internal (unreachable outside this repo), so it's kept only
// so the pkg/app default-registration wiring that still references it
// continues to compile; will be removed alongside the exported symbols it
// backs (CONFIG_KEY_ALLOWED_HOST_REGEXP, IsValidAuthHost) once those are
// confirmed unused downstream.
//
// Deprecated: use SNYK_DEFAULT_ALLOWED_HOST_DOMAINS (with
// auth.CONFIG_KEY_ALLOWED_HOSTS) via auth.IsValidSnykHost instead.
const SNYK_DEFAULT_ALLOWED_HOST_REGEXP = `^(https?://)?api(\.(.+))?\.(snyk|snykgov)\.io$`

// SNYK_DEFAULT_ALLOWED_HOST_DOMAINS is the default allowlist of registrable
// domains that an OAuth callback instance host is permitted to belong to.
var SNYK_DEFAULT_ALLOWED_HOST_DOMAINS = []string{"snyk.io", "snykgov.io"}

// DEFAULT_RETRY_EXCLUDED_PATH_SEGMENTS is the default deny-list of URL path segments
// excluded from GAF's network retries, shared between the pkg/app default-value
// registration and the pkg/networking/middleware fallback so the two cannot drift.
var DEFAULT_RETRY_EXCLUDED_PATH_SEGMENTS = []string{"monitor"}
