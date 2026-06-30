package logsummary

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type CLIVersion struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

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

func ParseCLIVersion(s string) (CLIVersion, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return CLIVersion{}, fmt.Errorf("empty version string")
	}

	// Strip pre-release suffix (e.g. "1.0.0-test" -> "1.0.0")
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

	return CLIVersion{Major: major, Minor: minor, Patch: patch, Raw: s}, nil
}

type VersionConstraint struct {
	MinInclusive CLIVersion
	MaxExclusive CLIVersion // zero value = unbounded
}

func (c VersionConstraint) Contains(v CLIVersion) bool {
	if v.Less(c.MinInclusive) {
		return false
	}
	if !c.MaxExclusive.IsZero() && !v.Less(c.MaxExclusive) {
		return false
	}
	return true
}

func versionRange(lower, upper string) VersionConstraint {
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
	return VersionConstraint{MinInclusive: minV, MaxExclusive: maxV}
}

type FormatSpec struct {
	ID            string
	Constraint    VersionConstraint
	Lexer         LexerSpec
	LandmarkRules []LandmarkRule
}

type FormatOption func(*FormatSpec)

func WithLexerOverrides(opts ...LexerOption) FormatOption {
	return func(s *FormatSpec) {
		s.Lexer = DeriveLexer(s.Lexer, opts...)
	}
}

func WithExtraLandmark(anchor Token, opens Section) FormatOption {
	return func(s *FormatSpec) {
		s.LandmarkRules = append(s.LandmarkRules, LandmarkRule{
			AnchorToken:  anchor,
			OpensSection: opens,
		})
	}
}

func WithReplacedLandmarks(rules ...LandmarkRule) FormatOption {
	return func(s *FormatSpec) {
		s.LandmarkRules = rules
	}
}

func DeriveFormat(parent FormatSpec, id string, constraint VersionConstraint, opts ...FormatOption) FormatSpec {
	spec := parent
	spec.ID = id
	spec.Constraint = constraint
	spec.LandmarkRules = append([]LandmarkRule{}, parent.LandmarkRules...)
	spec.Lexer.BodyClassifiers = append([]BodyClassifier{}, parent.Lexer.BodyClassifiers...)
	for _, opt := range opts {
		opt(&spec)
	}
	return spec
}

var (
	basePrefixRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+ \S+ - ?`)
	baseTableRe  = regexp.MustCompile(`^[A-Za-z][\w .-]*:`)
	responseRe   = regexp.MustCompile(`^< response \[0x[0-9a-fA-F]+\]:\s*[45]\d{2}\b`)
)

var baseLexer = LexerSpec{
	LinePrefixRe:   basePrefixRe,
	SummaryMarker:  "------------ Summary ------------",
	ErrorsMarker:   "------------ Errors ------------",
	VersionPrefix:  "Version:",
	ExitCodePrefix: "Exit Code:",
	TableRowRe:     baseTableRe,
	BodyClassifiers: []BodyClassifier{
		{Match: func(msg string) bool { return responseRe.MatchString(msg) }, Token: TokenHTTPError},
		{Match: func(msg string) bool { return strings.HasPrefix(msg, "< error:") }, Token: TokenCLIError},
		{Match: func(msg string) bool { return strings.HasPrefix(msg, "Failed ") }, Token: TokenFailedLine},
	},
}

var baseLandmarks = []LandmarkRule{
	{AnchorToken: TokenVersionLine, OpensSection: SectionHeader},
	{AnchorToken: TokenSummaryMarker, OpensSection: SectionSummary},
	{AnchorToken: TokenErrorsMarker, OpensSection: SectionResult},
	{AnchorToken: TokenExitCode, OpensSection: SectionResult},
}

var BaseSpec = FormatSpec{
	ID:            "base",
	Constraint:    versionRange("0.0.0", ""),
	Lexer:         baseLexer,
	LandmarkRules: baseLandmarks,
}

var registry = []FormatSpec{BaseSpec}

func extractCLIVersion(rawLines []string) (CLIVersion, bool) {
	versionPrefixes := []string{"Version:", "CLI Version:"}
	for _, line := range rawLines {
		stripped := line
		if loc := basePrefixRe.FindStringIndex(line); loc != nil {
			stripped = line[loc[1]:]
		}
		stripped = strings.TrimSpace(stripped)
		for _, prefix := range versionPrefixes {
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

func detectFormat(rawLines []string) FormatSpec {
	if ver, ok := extractCLIVersion(rawLines); ok {
		for _, spec := range registry {
			if spec.Constraint.Contains(ver) {
				return spec
			}
		}
	}
	return BaseSpec
}
