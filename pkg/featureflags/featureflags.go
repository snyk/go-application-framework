// Package featureflags is a minimal, dependency-free home for feature-flag surfaces shared
// between packages that can't import pkg/configuration directly (pkg/configuration already
// depends on pkg/utils transitively, via internal/utils, so pkg/utils importing
// pkg/configuration back would be an import cycle).
package featureflags

// FeatureFlagReader is satisfied by any configuration.Configuration.
type FeatureFlagReader interface {
	GetBool(key string) bool
}

const (
	// FileFilterMetacharacterFix backs configuration.FF_FILE_FILTER_METACHARACTER_FIX.
	FileFilterMetacharacterFix string = "internal_snyk_file_filter_metacharacter_fix_enabled"

	// FileFilterMetacharacterFixBackendName backs configuration.SNYK_FILE_FILTER_METACHARACTER_FIX.
	FileFilterMetacharacterFixBackendName string = "snykFileFilterMetacharacterFix"
)
