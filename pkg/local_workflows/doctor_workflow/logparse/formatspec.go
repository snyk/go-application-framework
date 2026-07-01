package logparse

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// FormatSpec bundles a lexer spec and landmark rules for a specific CLI version range.
type FormatSpec struct {
	ID            string
	Constraint    VersionConstraint
	Lexer         LexerSpec
	LandmarkRules []LandmarkRule
}

// FormatOption is a functional option applied when building or deriving a FormatSpec.
type FormatOption func(*FormatSpec)

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

// NewFormatSpec builds a FormatSpec. The landmark rules are copied so later
// mutation of the caller's slice does not affect the spec.
func NewFormatSpec(id string, constraint VersionConstraint, lexer LexerSpec, landmarks []LandmarkRule) FormatSpec {
	return FormatSpec{
		ID:            id,
		Constraint:    constraint,
		Lexer:         lexer,
		LandmarkRules: append([]LandmarkRule{}, landmarks...),
	}
}

// ---------------------------------------------------------------------------
// FormatOption constructors
// ---------------------------------------------------------------------------

func WithLexerOverrides(opts ...LexerOption) FormatOption {
	return func(s *FormatSpec) {
		s.Lexer = DeriveLexer(s.Lexer, opts...)
	}
}

func WithExtraLandmark(anchor Token, opens Section) FormatOption {
	return func(s *FormatSpec) {
		s.LandmarkRules = append(s.LandmarkRules, NewLandmarkRule(anchor, opens))
	}
}

func WithReplacedLandmarks(rules ...LandmarkRule) FormatOption {
	return func(s *FormatSpec) {
		s.LandmarkRules = append([]LandmarkRule{}, rules...)
	}
}

// ---------------------------------------------------------------------------
// DeriveFormat
// ---------------------------------------------------------------------------

// DeriveFormat creates a new FormatSpec by copying parent and applying overrides.
// Slices are deep-copied so mutations don't leak to the parent.
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
