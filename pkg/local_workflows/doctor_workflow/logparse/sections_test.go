package logparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	landmarks := FindLandmarks(tokens, testLandmarks)

	require.Len(t, landmarks, 4)
	assert.Equal(t, 1, landmarks[0].Index)
	assert.Equal(t, TokenVersionLine, landmarks[0].Token)
	assert.Equal(t, 4, landmarks[1].Index)
	assert.Equal(t, 6, landmarks[2].Index)
	assert.Equal(t, 7, landmarks[3].Index)
}

func TestFindLandmarks_noAnchors(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenPlain, "just text"),
		makeTok(2, TokenPlain, "more text"),
	}

	landmarks := FindLandmarks(tokens, testLandmarks)
	assert.Empty(t, landmarks)
}

func TestFindLandmarks_duplicateAnchors(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenSummaryMarker, "--- Summary ---"),
		makeTok(2, TokenPlain, "content"),
		makeTok(3, TokenSummaryMarker, "--- Summary ---"),
	}

	landmarks := FindLandmarks(tokens, testLandmarks)

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

	landmarks := FindLandmarks(tokens, testLandmarks)
	sections := SplitByLandmarks(tokens, landmarks, testLandmarks)

	require.Len(t, sections[SectionPreamble], 1)
	assert.Equal(t, "preamble", sections[SectionPreamble][0].Message)

	require.Len(t, sections[SectionHeader], 2)
	assert.Equal(t, TokenVersionLine, sections[SectionHeader][0].Token)

	require.Len(t, sections[SectionSummary], 2)
	assert.Equal(t, TokenSummaryMarker, sections[SectionSummary][0].Token)

	require.NotEmpty(t, sections[SectionResult])
	assert.Equal(t, TokenErrorsMarker, sections[SectionResult][0].Token)
}

func TestSplitByLandmarks_noLandmarks(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenPlain, "line 1"),
		makeTok(2, TokenPlain, "line 2"),
	}

	sections := SplitByLandmarks(tokens, nil, testLandmarks)

	assert.Len(t, sections[SectionBody], 2)
	assert.Empty(t, sections[SectionPreamble])
	assert.Empty(t, sections[SectionHeader])
}

func TestSplitByLandmarks_reorderedSections(t *testing.T) {
	// Landmarks are provided out of positional order; the splitter sorts them.
	tokens := []TokenizedLine{
		makeTok(1, TokenExitCode, "Exit Code: 2"),
		makeTok(2, TokenPlain, "trailing"),
		makeTok(3, TokenVersionLine, "Version: 1.0.0"),
		makeTok(4, TokenTableRow, "Platform: darwin"),
	}
	landmarks := []Landmark{
		NewLandmark(TokenVersionLine, 2),
		NewLandmark(TokenExitCode, 0),
	}

	sections := SplitByLandmarks(tokens, landmarks, testLandmarks)

	// ExitCode is first by index, so it opens the preamble-less first region.
	require.NotEmpty(t, sections[SectionResult])
	assert.Equal(t, TokenExitCode, sections[SectionResult][0].Token)
	require.NotEmpty(t, sections[SectionHeader])
	assert.Equal(t, TokenVersionLine, sections[SectionHeader][0].Token)
}

func TestSplitByLandmarks_adjacentLandmarks(t *testing.T) {
	tokens := []TokenizedLine{
		makeTok(1, TokenSummaryMarker, "--- Summary ---"),
		makeTok(2, TokenErrorsMarker, "--- Errors ---"),
		makeTok(3, TokenExitCode, "Exit Code: 0"),
	}

	landmarks := FindLandmarks(tokens, testLandmarks)
	sections := SplitByLandmarks(tokens, landmarks, testLandmarks)

	require.Len(t, sections[SectionSummary], 1)
	assert.Equal(t, TokenSummaryMarker, sections[SectionSummary][0].Token)
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

	header, rest := ExtractHeaderFromRegion(region)

	require.Len(t, header, 3)
	assert.Equal(t, "Version: 1.0.0", header[0].Message)
	assert.Equal(t, "  Configuration: ok", header[2].Message)

	require.Len(t, rest, 2)
	assert.Contains(t, rest[0].Message, "request")
}

func TestExtractHeaderFromRegion_emptyRegion(t *testing.T) {
	header, rest := ExtractHeaderFromRegion(nil)
	assert.Nil(t, header)
	assert.Nil(t, rest)
}

func TestExtractHeaderFromRegion_noVersionLine(t *testing.T) {
	region := []TokenizedLine{
		makeTok(1, TokenPlain, "some plain line"),
		makeTok(2, TokenPlain, "another line"),
	}

	header, rest := ExtractHeaderFromRegion(region)

	assert.Nil(t, header)
	require.Len(t, rest, 2)
}

func TestExtractHeaderFromRegion_versionLineOnly(t *testing.T) {
	region := []TokenizedLine{
		makeTok(1, TokenVersionLine, "Version: 1.0.0"),
	}

	header, rest := ExtractHeaderFromRegion(region)

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

	header, rest := ExtractHeaderFromRegion(region)

	require.Len(t, header, 2)
	require.Len(t, rest, 1)
}
