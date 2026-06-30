package logsummary

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenize_classifiesAllBaseTokenTypes(t *testing.T) {
	lines := []string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main -   Configuration:       all good",
		"2026-06-10T13:10:38Z main - < response [0xbbb]: 401 Unauthorized",
		"2026-06-10T13:10:38Z main - < error: auth failed",
		"2026-06-10T13:10:38Z main - Failed to connect: timeout",
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"2026-06-10T13:10:38Z main - ------------ Errors ------------",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
		"2026-06-10T13:10:38Z main - > request [0xaaa]: GET https://api.snyk.io",
		"",
	}

	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, len(lines))

	assert.Equal(t, TokenVersionLine, tokens[0].Token, "Version line")
	assert.Equal(t, TokenTableRow, tokens[1].Token, "Platform table row")
	assert.Equal(t, TokenTableRow, tokens[2].Token, "Indented table row")
	assert.Equal(t, TokenHTTPError, tokens[3].Token, "HTTP 401 error")
	assert.Equal(t, TokenCLIError, tokens[4].Token, "CLI error")
	assert.Equal(t, TokenFailedLine, tokens[5].Token, "Failed line")
	assert.Equal(t, TokenSummaryMarker, tokens[6].Token, "Summary marker")
	assert.Equal(t, TokenErrorsMarker, tokens[7].Token, "Errors marker")
	assert.Equal(t, TokenExitCode, tokens[8].Token, "Exit code")
	assert.Equal(t, TokenPlain, tokens[9].Token, "Request line is plain")
	assert.Equal(t, TokenBlank, tokens[10].Token, "Empty line is blank")
}

func TestTokenize_stripsTimestampPrefix(t *testing.T) {
	lines := []string{"2026-06-10T13:10:38Z main - Version:               1.0.0"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)

	assert.Equal(t, "Version:               1.0.0", tokens[0].Message)
	assert.True(t, tokens[0].HasCLIPrefix)
	assert.Equal(t, 1, tokens[0].Number)
}

func TestTokenize_unprefixedLine(t *testing.T) {
	lines := []string{"some random output without timestamp"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)

	assert.False(t, tokens[0].HasCLIPrefix)
	assert.Equal(t, "some random output without timestamp", tokens[0].Message)
	assert.Equal(t, tokens[0].RawText, tokens[0].Message)
}

func TestTokenize_blankLineIsTokenBlank(t *testing.T) {
	lines := []string{"", "   ", "\t"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 3)

	for i, tok := range tokens {
		assert.Equal(t, TokenBlank, tok.Token, "line %d should be blank", i)
	}
}

func TestTokenize_firstClassifierWins(t *testing.T) {
	// "< error:" matches both CLE error prefix and could hypothetically match others.
	// Ensure the first classifier (HTTP response) doesn't match and CLI error does.
	lines := []string{"2026-06-10T13:10:38Z main - < error: something"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenCLIError, tokens[0].Token)
}

func TestTokenize_summaryMarkerMustBeExact(t *testing.T) {
	lines := []string{
		"2026-06-10T13:10:38Z main - Failed to parse ------------ Summary ------------",
	}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)

	// The marker is embedded in a longer message, should NOT be TokenSummaryMarker
	assert.NotEqual(t, TokenSummaryMarker, tokens[0].Token)
}

func TestTokenize_CRLFhandling(t *testing.T) {
	lines := strings.Split("2026-06-10T13:10:38Z main - Version:               1.0.0\r\n2026-06-10T13:10:38Z main - Exit Code:             2\r\n", "\n")
	tokens := tokenize(baseLexer, lines)

	// After split on \n, lines will have trailing \r which tokenize should strip
	versionTok := tokens[0]
	assert.Equal(t, TokenVersionLine, versionTok.Token)
	assert.False(t, strings.HasSuffix(versionTok.Message, "\r"), "\\r should be stripped from message")
}

func TestTokenize_200ResponseIsPlain(t *testing.T) {
	lines := []string{"2026-06-10T13:10:38Z main - < response [0xbbb]: 200 OK"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenPlain, tokens[0].Token)
}

func TestTokenize_304ResponseIsPlain(t *testing.T) {
	lines := []string{"2026-06-10T13:10:38Z main - < response [0xbbb]: 304 Not Modified"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenPlain, tokens[0].Token)
}

func TestTokenize_failedWithoutSpaceIsPlain(t *testing.T) {
	lines := []string{"2026-06-10T13:10:38Z main - FailedOverNode rebalancing"}
	tokens := tokenize(baseLexer, lines)
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenPlain, tokens[0].Token)
}
