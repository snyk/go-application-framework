package logparse

import (
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// CLIVersion represents a parsed "major.minor.patch" from the log's Version line.
type CLIVersion struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

// VersionConstraint defines a half-open range [MinInclusive, MaxExclusive).
// A zero-value MaxExclusive means "no upper bound."
type VersionConstraint struct {
	MinInclusive CLIVersion
	MaxExclusive CLIVersion
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

// NewCLIVersion builds a CLIVersion from its components.
func NewCLIVersion(major, minor, patch int, raw string) CLIVersion {
	return CLIVersion{Major: major, Minor: minor, Patch: patch, Raw: raw}
}

// NewVersionConstraint builds a VersionConstraint from parsed versions. A
// zero-value maxExclusive means the range has no upper bound.
func NewVersionConstraint(minInclusive, maxExclusive CLIVersion) VersionConstraint {
	return VersionConstraint{MinInclusive: minInclusive, MaxExclusive: maxExclusive}
}

// ParseCLIVersion parses a version string like "1.1200.0" or "1.0.0-test".
func ParseCLIVersion(s string) (CLIVersion, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return CLIVersion{}, fmt.Errorf("empty version string")
	}

	base := s
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		base = s[:idx]
	}

	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return CLIVersion{}, fmt.Errorf("expected 3 dot-separated components, got %d in %q", len(parts), s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return CLIVersion{}, fmt.Errorf("invalid major version %q: %w", parts[0], err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return CLIVersion{}, fmt.Errorf("invalid minor version %q: %w", parts[1], err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return CLIVersion{}, fmt.Errorf("invalid patch version %q: %w", parts[2], err)
	}

	return NewCLIVersion(major, minor, patch, s), nil
}

// VersionRange builds a VersionConstraint from version strings. An empty upper
// bound means the range is unbounded above. It panics on malformed input, so it
// is intended for use with compile-time constant version literals.
func VersionRange(lower, upper string) VersionConstraint {
	minV, err := ParseCLIVersion(lower)
	if err != nil {
		panic(fmt.Sprintf("invalid min version %q: %v", lower, err))
	}
	var maxV CLIVersion
	if upper != "" {
		maxV, err = ParseCLIVersion(upper)
		if err != nil {
			panic(fmt.Sprintf("invalid max version %q: %v", upper, err))
		}
	}
	return NewVersionConstraint(minV, maxV)
}

// ---------------------------------------------------------------------------
// CLIVersion methods
// ---------------------------------------------------------------------------

func (v CLIVersion) IsZero() bool {
	return v.Major == 0 && v.Minor == 0 && v.Patch == 0 && v.Raw == ""
}

func (v CLIVersion) Less(other CLIVersion) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

// ---------------------------------------------------------------------------
// VersionConstraint methods
// ---------------------------------------------------------------------------

func (c VersionConstraint) Contains(v CLIVersion) bool {
	if v.Less(c.MinInclusive) {
		return false
	}
	if !c.MaxExclusive.IsZero() && !v.Less(c.MaxExclusive) {
		return false
	}
	return true
}
