package logsummary

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// DeriveLexer
// =============================================================================

func TestDeriveLexer_inheritsParentFields(t *testing.T) {
	child := DeriveLexer(baseLexer)

	assert.Equal(t, baseLexer.SummaryMarker, child.SummaryMarker)
	assert.Equal(t, baseLexer.ErrorsMarker, child.ErrorsMarker)
	assert.Equal(t, baseLexer.VersionPrefix, child.VersionPrefix)
	assert.Equal(t, baseLexer.ExitCodePrefix, child.ExitCodePrefix)
	assert.Equal(t, baseLexer.LinePrefixRe.String(), child.LinePrefixRe.String())
	assert.Equal(t, baseLexer.TableRowRe.String(), child.TableRowRe.String())
	assert.Equal(t, len(baseLexer.BodyClassifiers), len(child.BodyClassifiers))
}

func TestDeriveLexer_overridesOnlySpecifiedField(t *testing.T) {
	newMarker := "============ Summary ============"
	child := DeriveLexer(baseLexer, WithSummaryMarker(newMarker))

	assert.Equal(t, newMarker, child.SummaryMarker)
	// Everything else unchanged
	assert.Equal(t, baseLexer.ErrorsMarker, child.ErrorsMarker)
	assert.Equal(t, baseLexer.VersionPrefix, child.VersionPrefix)
	assert.Equal(t, baseLexer.ExitCodePrefix, child.ExitCodePrefix)
	assert.Equal(t, len(baseLexer.BodyClassifiers), len(child.BodyClassifiers))
}

func TestDeriveLexer_extraClassifierPrepended(t *testing.T) {
	parentLen := len(baseLexer.BodyClassifiers)
	child := DeriveLexer(baseLexer, WithExtraClassifier(
		func(msg string) bool { return strings.HasPrefix(msg, "FATAL ") },
		TokenCLIError,
	))

	assert.Equal(t, parentLen+1, len(child.BodyClassifiers))
	// The new classifier should be first (takes priority)
	assert.True(t, child.BodyClassifiers[0].Match("FATAL something"))
	assert.False(t, child.BodyClassifiers[0].Match("Not fatal"))
}

func TestDeriveLexer_parentNotMutated(t *testing.T) {
	originalLen := len(baseLexer.BodyClassifiers)
	originalMarker := baseLexer.SummaryMarker

	_ = DeriveLexer(baseLexer,
		WithSummaryMarker("changed"),
		WithExtraClassifier(func(string) bool { return true }, TokenCLIError),
	)

	assert.Equal(t, originalLen, len(baseLexer.BodyClassifiers))
	assert.Equal(t, originalMarker, baseLexer.SummaryMarker)
}

func TestDeriveLexer_linePrefixReOverride(t *testing.T) {
	newRe := regexp.MustCompile(`^\[.+?\] `)
	child := DeriveLexer(baseLexer, WithLinePrefixRe(newRe))

	assert.Equal(t, newRe.String(), child.LinePrefixRe.String())
	assert.Equal(t, baseLexer.LinePrefixRe.String() != newRe.String(), true)
}

func TestDeriveLexer_versionPrefixOverride(t *testing.T) {
	child := DeriveLexer(baseLexer, WithVersionPrefix("CLI Version:"))
	assert.Equal(t, "CLI Version:", child.VersionPrefix)
	assert.Equal(t, "Version:", baseLexer.VersionPrefix) // parent unchanged
}

// =============================================================================
// DeriveFormat
// =============================================================================

func TestDeriveFormat_inheritsLandmarkRules(t *testing.T) {
	child := DeriveFormat(BaseSpec, "child", versionRange("1.0.0", "2.0.0"))

	assert.Equal(t, len(BaseSpec.LandmarkRules), len(child.LandmarkRules))
	assert.Equal(t, "child", child.ID)
}

func TestDeriveFormat_extraLandmark(t *testing.T) {
	parentLen := len(BaseSpec.LandmarkRules)
	child := DeriveFormat(BaseSpec, "child", versionRange("1.0.0", "2.0.0"),
		WithExtraLandmark(TokenPlain, SectionBody), // hypothetical
	)

	assert.Equal(t, parentLen+1, len(child.LandmarkRules))
}

func TestDeriveFormat_parentNotMutated(t *testing.T) {
	originalLen := len(BaseSpec.LandmarkRules)

	_ = DeriveFormat(BaseSpec, "child", versionRange("1.0.0", "2.0.0"),
		WithExtraLandmark(TokenPlain, SectionBody),
	)

	assert.Equal(t, originalLen, len(BaseSpec.LandmarkRules))
}

func TestDeriveFormat_lexerOverrides(t *testing.T) {
	child := DeriveFormat(BaseSpec, "child", versionRange("1.0.0", "2.0.0"),
		WithLexerOverrides(
			WithSummaryMarker("=== Summary ==="),
		),
	)

	assert.Equal(t, "=== Summary ===", child.Lexer.SummaryMarker)
	assert.Equal(t, BaseSpec.Lexer.ErrorsMarker, child.Lexer.ErrorsMarker)
}

func TestDeriveFormat_replacedLandmarks(t *testing.T) {
	newRules := []LandmarkRule{
		{AnchorToken: TokenVersionLine, OpensSection: SectionHeader},
		{AnchorToken: TokenExitCode, OpensSection: SectionResult},
	}
	child := DeriveFormat(BaseSpec, "minimal", versionRange("1.0.0", ""),
		WithReplacedLandmarks(newRules...),
	)

	require.Len(t, child.LandmarkRules, 2)
	assert.Equal(t, TokenVersionLine, child.LandmarkRules[0].AnchorToken)
	assert.Equal(t, TokenExitCode, child.LandmarkRules[1].AnchorToken)
}

// =============================================================================
// Multi-version integration (extensibility proof)
// =============================================================================

func TestDeriveFormat_derivedSpecTokenizesCorrectly(t *testing.T) {
	// Create a v2 spec that uses a different summary marker
	v2Lexer := DeriveLexer(baseLexer, WithSummaryMarker("============ Summary ============"))
	v2Spec := DeriveFormat(BaseSpec, "v2", versionRange("2.0.0", ""),
		WithLexerOverrides(WithSummaryMarker("============ Summary ============")),
	)

	// Old marker should be plain in v2
	oldMarkerLines := []string{"------------ Summary ------------"}
	oldTokens := tokenize(v2Lexer, oldMarkerLines)
	assert.Equal(t, TokenPlain, oldTokens[0].Token, "old marker should be plain in v2")

	// New marker should be recognized
	newMarkerLines := []string{"============ Summary ============"}
	newTokens := tokenize(v2Spec.Lexer, newMarkerLines)
	assert.Equal(t, TokenSummaryMarker, newTokens[0].Token, "new marker should be recognized in v2")

	// Original baseLexer should still recognize old marker
	baseTokens := tokenize(baseLexer, oldMarkerLines)
	assert.Equal(t, TokenSummaryMarker, baseTokens[0].Token, "base should still recognize old marker")
}
