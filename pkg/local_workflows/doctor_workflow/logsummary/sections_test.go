package logsummary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTok(number int, token Token, msg string) TokenizedLine {
	return TokenizedLine{Number: number, Message: msg, Token: token, HasCLIPrefix: true}
}

func TestFindLandmarks_findsAllAnchors(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenPlain, "preamble"),
		makeTok(2, TokenVersionLine, "Version: 1.0.0"),
		makeTok(3, TokenTableRow, "Platform: darwin"),
		makeTok(4, TokenPlain, "body line"),
		makeTok(5, TokenSummaryMarker, "--- Summary ---"),
		makeTok(6, TokenPlain, "summary content"),
		makeTok(7, TokenErrorsMarker, "--- Errors ---"),
		makeTok(8, TokenExitCode, "Exit Code: 2"),
	}

	landmarks := findLandmarks(tokens, baseLandmarks)

	require.Len(t, landmarks, 4)
	assert.Equal(t, 1, landmarks[0].Index) // VersionLine
	assert.Equal(t, TokenVersionLine, landmarks[0].Token)
	assert.Equal(t, 4, landmarks[1].Index) // SummaryMarker
	assert.Equal(t, 6, landmarks[2].Index) // ErrorsMarker
	assert.Equal(t, 7, landmarks[3].Index) // ExitCode
}

func TestFindLandmarks_noAnchors(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenPlain, "just text"),
		makeTok(2, TokenPlain, "more text"),
	}

	landmarks := findLandmarks(tokens, baseLandmarks)
	assert.Empty(t, landmarks)
}

func TestFindLandmarks_duplicateAnchors(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenSummaryMarker, "--- Summary ---"),
		makeTok(2, TokenPlain, "content"),
		makeTok(3, TokenSummaryMarker, "--- Summary ---"),
	}

	landmarks := findLandmarks(tokens, baseLandmarks)

	// Both should be found - splitByLandmarks will handle priority
	require.Len(t, landmarks, 2)
	assert.Equal(t, 0, landmarks[0].Index)
	assert.Equal(t, 2, landmarks[1].Index)
}

func TestSplitByLandmarks_standardLayout(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenPlain, "preamble"),
		makeTok(2, TokenVersionLine, "Version: 1.0.0"),
		makeTok(3, TokenTableRow, "Platform: darwin"),
		makeTok(4, TokenSummaryMarker, "--- Summary ---"),
		makeTok(5, TokenPlain, "summary content"),
		makeTok(6, TokenErrorsMarker, "--- Errors ---"),
		makeTok(7, TokenPlain, "error detail"),
		makeTok(8, TokenExitCode, "Exit Code: 2"),
	}

	landmarks := findLandmarks(tokens, baseLandmarks)
	sections := splitByLandmarks(tokens, landmarks, baseLandmarks)

	// Preamble: tokens before first landmark
	require.Len(t, sections[SectionPreamble], 1)
	assert.Equal(t, "preamble", sections[SectionPreamble][0].Message)

	// Header: VersionLine + table rows until next landmark
	require.Len(t, sections[SectionHeader], 2)
	assert.Equal(t, TokenVersionLine, sections[SectionHeader][0].Token)

	// Summary section
	require.Len(t, sections[SectionSummary], 2)
	assert.Equal(t, TokenSummaryMarker, sections[SectionSummary][0].Token)

	// Result section: ErrorsMarker + ExitCode
	require.NotEmpty(t, sections[SectionResult])
	assert.Equal(t, TokenErrorsMarker, sections[SectionResult][0].Token)
}

func TestSplitByLandmarks_noLandmarks(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenPlain, "line 1"),
		makeTok(2, TokenPlain, "line 2"),
	}

	sections := splitByLandmarks(tokens, nil, baseLandmarks)

	assert.Len(t, sections[SectionBody], 2)
	assert.Empty(t, sections[SectionPreamble])
	assert.Empty(t, sections[SectionHeader])
}

func TestSplitByLandmarks_adjacentLandmarks(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenSummaryMarker, "--- Summary ---"),
		makeTok(2, TokenErrorsMarker, "--- Errors ---"),
		makeTok(3, TokenExitCode, "Exit Code: 0"),
	}

	landmarks := findLandmarks(tokens, baseLandmarks)
	sections := splitByLandmarks(tokens, landmarks, baseLandmarks)

	require.Len(t, sections[SectionSummary], 1)
	assert.Equal(t, TokenSummaryMarker, sections[SectionSummary][0].Token)

	// ErrorsMarker and ExitCode both open SectionResult
	require.NotEmpty(t, sections[SectionResult])
}

func TestExtractHeaderFromRegion_stopsAtNonTableRow(t *testing.T) {
	region := []TokenizedLine{
		makeTok(1, TokenVersionLine, "Version: 1.0.0"),
		makeTok(2, TokenTableRow, "Platform: darwin"),
		makeTok(3, TokenTableRow, "  Configuration: ok"),
		makeTok(4, TokenPlain, "> request [0xaaa]: GET https://api.snyk.io"),
		makeTok(5, TokenPlain, "more body"),
	}

	header, rest := extractHeaderFromRegion(region)

	require.Len(t, header, 3)
	assert.Equal(t, "Version: 1.0.0", header[0].Message)
	assert.Equal(t, "  Configuration: ok", header[2].Message)

	require.Len(t, rest, 2)
	assert.Contains(t, rest[0].Message, "request")
}

func TestExtractHeaderFromRegion_emptyRegion(t *testing.T) {
	header, rest := extractHeaderFromRegion(nil)
	assert.Nil(t, header)
	assert.Nil(t, rest)
}

func TestExtractHeaderFromRegion_noVersionLine(t *testing.T) {
	region := []TokenizedLine{
		makeTok(1, TokenPlain, "some plain line"),
		makeTok(2, TokenPlain, "another line"),
	}

	header, rest := extractHeaderFromRegion(region)

	assert.Nil(t, header)
	require.Len(t, rest, 2)
}

func TestExtractHeaderFromRegion_versionLineOnly(t *testing.T) {
	region := []TokenizedLine{
		makeTok(1, TokenVersionLine, "Version: 1.0.0"),
	}

	header, rest := extractHeaderFromRegion(region)

	require.Len(t, header, 1)
	assert.Equal(t, "Version: 1.0.0", header[0].Message)
	assert.Empty(t, rest)
}

func TestExtractHeaderFromRegion_trailingBlanksExcluded(t *testing.T) {
	region := []TokenizedLine{
		makeTok(1, TokenVersionLine, "Version: 1.0.0"),
		makeTok(2, TokenTableRow, "Platform: darwin"),
		makeTok(3, TokenBlank, ""),
		makeTok(4, TokenBlank, ""),
		makeTok(5, TokenPlain, "body line"),
	}

	header, rest := extractHeaderFromRegion(region)

	require.Len(t, header, 2) // Version + Platform, blanks trimmed
	require.Len(t, rest, 1)   // body line (blanks consumed)
}
