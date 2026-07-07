package diagnosis

import "strings"

// refineFindings drops findings that reflect normal CLI behavior rather than a
// real problem, so doctor surfaces only what matters. It is the single,
// extensible place for "what doctor ignores" - add new benign rules to isBenign.
//
// It removes (rather than never-creating) so the analyzer stays purely factual;
// switching a rule from drop to downgrade (e.g. set Severity to info) is a local
// change here.
func refineFindings(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if isBenign(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// isBenign reports whether a finding is expected/normal and not worth surfacing.
func isBenign(f Finding) bool {
	return isFeatureFlag403(f)
}

// isFeatureFlag403 recognizes the CLI probing a feature flag: the feature-flags
// endpoint returns 403 when the org simply does not have the flag enabled, which
// is normal behavior, not a failure doctor should report.
func isFeatureFlag403(f Finding) bool {
	if f.Kind != KindCorrelation || f.Fields[FieldStatus] != "403" {
		return false
	}
	if strings.Contains(f.Fields[FieldURL], "/cli-config/feature-flags/") {
		return true
	}
	return strings.Contains(strings.ToLower(f.Message), "feature enabled")
}
