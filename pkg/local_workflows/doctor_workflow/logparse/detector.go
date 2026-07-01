package logparse

import (
	"regexp"
	"strings"
)

// Detector selects a FormatSpec for a log by extracting its declared CLI
// version and matching it against a registry of specs.
type Detector struct {
	LinePrefixRe    *regexp.Regexp
	VersionPrefixes []string
	Registry        []FormatSpec
	Fallback        FormatSpec
}

// NewDetector builds a Detector. The registry is tried in order; the first spec
// whose constraint contains the detected version wins. When no version can be
// extracted (or none matches), Detect returns the fallback spec.
func NewDetector(linePrefixRe *regexp.Regexp, versionPrefixes []string, registry []FormatSpec, fallback FormatSpec) *Detector {
	return &Detector{
		LinePrefixRe:    linePrefixRe,
		VersionPrefixes: append([]string{}, versionPrefixes...),
		Registry:        append([]FormatSpec{}, registry...),
		Fallback:        fallback,
	}
}

// ExtractCLIVersion scans raw lines for a version field and parses it.
func (d *Detector) ExtractCLIVersion(rawLines []string) (CLIVersion, bool) {
	for _, line := range rawLines {
		stripped := line
		if d.LinePrefixRe != nil {
			if loc := d.LinePrefixRe.FindStringIndex(line); loc != nil {
				stripped = line[loc[1]:]
			}
		}
		stripped = strings.TrimSpace(stripped)
		for _, prefix := range d.VersionPrefixes {
			if strings.HasPrefix(stripped, prefix) {
				verStr := strings.TrimSpace(stripped[len(prefix):])
				if v, err := ParseCLIVersion(verStr); err == nil {
					return v, true
				}
			}
		}
	}
	return CLIVersion{}, false
}

// Detect returns the FormatSpec matching the log's declared version, or the
// fallback spec when the version is absent or unmatched.
func (d *Detector) Detect(rawLines []string) FormatSpec {
	if ver, ok := d.ExtractCLIVersion(rawLines); ok {
		for _, spec := range d.Registry {
			if spec.Constraint.Contains(ver) {
				return spec
			}
		}
	}
	return d.Fallback
}
