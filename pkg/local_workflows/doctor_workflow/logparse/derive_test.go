package logparse

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
	child := DeriveLexer(testLexer)

	assert.Equal(t, testLexer.SummaryMarker, child.SummaryMarker)
	assert.Equal(t, testLexer.ErrorsMarker, child.ErrorsMarker)
	assert.Equal(t, testLexer.VersionPrefix, child.VersionPrefix)
	assert.Equal(t, testLexer.ExitCodePrefix, child.ExitCodePrefix)
	assert.Equal(t, testLexer.LinePrefixRe.String(), child.LinePrefixRe.String())
	assert.Equal(t, testLexer.TableRowRe.String(), child.TableRowRe.String())
	assert.Equal(t, len(testLexer.BodyClassifiers), len(child.BodyClassifiers))
}

func TestDeriveLexer_overridesOnlySpecifiedField(t *testing.T) {
	newMarker := "============ Summary ============"
	child := DeriveLexer(testLexer, WithSummaryMarker(newMarker))

	assert.Equal(t, newMarker, child.SummaryMarker)
	assert.Equal(t, testLexer.ErrorsMarker, child.ErrorsMarker)
	assert.Equal(t, testLexer.VersionPrefix, child.VersionPrefix)
	assert.Equal(t, testLexer.ExitCodePrefix, child.ExitCodePrefix)
	assert.Equal(t, len(testLexer.BodyClassifiers), len(child.BodyClassifiers))
}

func TestDeriveLexer_extraClassifierPrepended(t *testing.T) {
	parentLen := len(testLexer.BodyClassifiers)
	child := DeriveLexer(testLexer, WithExtraClassifier(
		func(msg string) bool { return strings.HasPrefix(msg, "FATAL ") },
		TokenCLIError,
	))

	assert.Equal(t, parentLen+1, len(child.BodyClassifiers))
	assert.True(t, child.BodyClassifiers[0].Match("FATAL something"))
	assert.False(t, child.BodyClassifiers[0].Match("Not fatal"))
}

func TestDeriveLexer_parentNotMutated(t *testing.T) {
	originalLen := len(testLexer.BodyClassifiers)
	originalMarker := testLexer.SummaryMarker

	_ = DeriveLexer(testLexer,
		WithSummaryMarker("changed"),
		WithExtraClassifier(func(string) bool { return true }, TokenCLIError),
	)

	assert.Equal(t, originalLen, len(testLexer.BodyClassifiers))
	assert.Equal(t, originalMarker, testLexer.SummaryMarker)
}

func TestDeriveLexer_linePrefixReOverride(t *testing.T) {
	newRe := regexp.MustCompile(`^\[.+?\] `)
	child := DeriveLexer(testLexer, WithLinePrefixRe(newRe))

	assert.Equal(t, newRe.String(), child.LinePrefixRe.String())
	assert.NotEqual(t, testLexer.LinePrefixRe.String(), child.LinePrefixRe.String())
}

func TestDeriveLexer_versionPrefixOverride(t *testing.T) {
	child := DeriveLexer(testLexer, WithVersionPrefix("CLI Version:"))
	assert.Equal(t, "CLI Version:", child.VersionPrefix)
	assert.Equal(t, "Version:", testLexer.VersionPrefix)
}

// =============================================================================
// DeriveFormat
// =============================================================================

func TestDeriveFormat_inheritsLandmarkRules(t *testing.T) {
	child := DeriveFormat(testSpec, "child", VersionRange("1.0.0", "2.0.0"))

	assert.Equal(t, len(testSpec.LandmarkRules), len(child.LandmarkRules))
	assert.Equal(t, "child", child.ID)
}

func TestDeriveFormat_extraLandmark(t *testing.T) {
	parentLen := len(testSpec.LandmarkRules)
	child := DeriveFormat(testSpec, "child", VersionRange("1.0.0", "2.0.0"),
		WithExtraLandmark(TokenPlain, SectionBody),
	)

	assert.Equal(t, parentLen+1, len(child.LandmarkRules))
}

func TestDeriveFormat_parentNotMutated(t *testing.T) {
	originalLen := len(testSpec.LandmarkRules)

	_ = DeriveFormat(testSpec, "child", VersionRange("1.0.0", "2.0.0"),
		WithExtraLandmark(TokenPlain, SectionBody),
	)

	assert.Equal(t, originalLen, len(testSpec.LandmarkRules))
}

func TestDeriveFormat_lexerOverrides(t *testing.T) {
	child := DeriveFormat(testSpec, "child", VersionRange("1.0.0", "2.0.0"),
		WithLexerOverrides(
			WithSummaryMarker("=== Summary ==="),
		),
	)

	assert.Equal(t, "=== Summary ===", child.Lexer.SummaryMarker)
	assert.Equal(t, testSpec.Lexer.ErrorsMarker, child.Lexer.ErrorsMarker)
}

func TestDeriveFormat_replacedLandmarks(t *testing.T) {
	newRules := []LandmarkRule{
		NewLandmarkRule(TokenVersionLine, SectionHeader),
		NewLandmarkRule(TokenExitCode, SectionResult),
	}
	child := DeriveFormat(testSpec, "minimal", VersionRange("1.0.0", ""),
		WithReplacedLandmarks(newRules...),
	)

	require.Len(t, child.LandmarkRules, 2)
	assert.Equal(t, TokenVersionLine, child.LandmarkRules[0].AnchorToken)
	assert.Equal(t, TokenExitCode, child.LandmarkRules[1].AnchorToken)
}

func TestDeriveFormat_derivedSpecTokenizesCorrectly(t *testing.T) {
	v2Lexer := DeriveLexer(testLexer, WithSummaryMarker("============ Summary ============"))
	v2Spec := DeriveFormat(testSpec, "v2", VersionRange("2.0.0", ""),
		WithLexerOverrides(WithSummaryMarker("============ Summary ============")),
	)

	oldMarkerLines := []string{"------------ Summary ------------"}
	oldTokens := Tokenize(v2Lexer, oldMarkerLines)
	assert.Equal(t, TokenPlain, oldTokens[0].Token, "old marker should be plain in v2")

	newMarkerLines := []string{"============ Summary ============"}
	newTokens := Tokenize(v2Spec.Lexer, newMarkerLines)
	assert.Equal(t, TokenSummaryMarker, newTokens[0].Token, "new marker should be recognized in v2")

	baseTokens := Tokenize(testLexer, oldMarkerLines)
	assert.Equal(t, TokenSummaryMarker, baseTokens[0].Token, "base should still recognize old marker")
}
