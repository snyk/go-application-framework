// Package featureflags is a minimal, dependency-free home for feature-flag surfaces shared
// between packages that can't import pkg/configuration directly (pkg/configuration already
// depends on pkg/utils transitively, via internal/utils, so pkg/utils importing
// pkg/configuration back would be an import cycle).
package featureflags

// FeatureFlagReader is satisfied by any configuration.Configuration.
type FeatureFlagReader interface {
	GetBool(key string) bool
}

// These fields back pkg/configuration/constants.go
const (
	FileFilterMetacharacterFix          string = "internal_snyk_file_filter_metacharacter_fix_enabled"
	GitIgnoreRespectTrackedFiles        string = "internal_snyk_gitignore_respect_tracked_files_enabled"
	FileFilterRespectParentExclusionFix string = "internal_snyk_file_filter_respect_parent_exclusion_enabled"

	FileFilterMetacharacterFixBackendName          string = "snykFileFilterMetacharacterFix"
	GitIgnoreRespectTrackedFilesBackendName        string = "snykGitIgnoreTrackedFiles"
	FileFilterRespectParentExclusionFixBackendName string = "snykFileFilterRespectParentExclusion"
)
