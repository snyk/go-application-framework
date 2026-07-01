package logparse

import "sort"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Section identifies a region of the parsed log.
type Section string

const (
	SectionPreamble Section = "preamble"
	SectionHeader   Section = "header"
	SectionBody     Section = "body"
	SectionSummary  Section = "summary"
	SectionResult   Section = "result"
)

// Landmark is a structural anchor found in the token stream.
type Landmark struct {
	Token Token
	Index int
}

// LandmarkRule maps an anchor token to the section it opens.
type LandmarkRule struct {
	AnchorToken  Token
	OpensSection Section
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

// NewLandmark builds a Landmark.
func NewLandmark(token Token, index int) Landmark {
	return Landmark{Token: token, Index: index}
}

// NewLandmarkRule builds a LandmarkRule.
func NewLandmarkRule(anchor Token, opens Section) LandmarkRule {
	return LandmarkRule{AnchorToken: anchor, OpensSection: opens}
}

// ---------------------------------------------------------------------------
// Landmark scanning (Phase 2a of the pipeline)
// ---------------------------------------------------------------------------

// FindLandmarks scans tokens for all anchor positions defined by the rules.
func FindLandmarks(tokens []TokenizedLine, rules []LandmarkRule) []Landmark {
	anchorSet := make(map[Token]struct{}, len(rules))
	for _, r := range rules {
		anchorSet[r.AnchorToken] = struct{}{}
	}
	var landmarks []Landmark
	for i, tok := range tokens {
		if _, ok := anchorSet[tok.Token]; ok {
			landmarks = append(landmarks, NewLandmark(tok.Token, i))
		}
	}
	return landmarks
}

// ---------------------------------------------------------------------------
// Section splitting (Phase 2b of the pipeline)
// ---------------------------------------------------------------------------

// SplitByLandmarks carves the token stream into named regions using landmark
// positions. Lines before the first landmark go into SectionPreamble (or
// SectionBody when there are no landmarks at all).
func SplitByLandmarks(tokens []TokenizedLine, landmarks []Landmark, rules []LandmarkRule) map[Section][]TokenizedLine {
	ruleMap := make(map[Token]Section, len(rules))
	for _, r := range rules {
		ruleMap[r.AnchorToken] = r.OpensSection
	}

	sort.Slice(landmarks, func(i, j int) bool {
		return landmarks[i].Index < landmarks[j].Index
	})

	sections := make(map[Section][]TokenizedLine)

	if len(landmarks) == 0 {
		sections[SectionBody] = tokens
		return sections
	}

	if landmarks[0].Index > 0 {
		sections[SectionPreamble] = tokens[:landmarks[0].Index]
	}

	for i, lm := range landmarks {
		sec := ruleMap[lm.Token]
		var end int
		if i+1 < len(landmarks) {
			end = landmarks[i+1].Index
		} else {
			end = len(tokens)
		}
		sections[sec] = append(sections[sec], tokens[lm.Index:end]...)
	}

	return sections
}

// ---------------------------------------------------------------------------
// Header extraction
// ---------------------------------------------------------------------------

// ExtractHeaderFromRegion finds the version line and its trailing table rows
// within a region. Returns (header tokens, remaining body tokens).
func ExtractHeaderFromRegion(region []TokenizedLine) (header, rest []TokenizedLine) {
	if len(region) == 0 {
		return nil, nil
	}

	start := -1
	for i, tok := range region {
		if tok.Token == TokenVersionLine {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, region
	}

	end := start + 1
	for end < len(region) {
		tok := region[end]
		if tok.Token == TokenTableRow || tok.Token == TokenBlank {
			end++
			continue
		}
		break
	}

	headerEnd := end
	for headerEnd > start && region[headerEnd-1].Token == TokenBlank {
		headerEnd--
	}

	header = region[start:headerEnd]
	var remaining []TokenizedLine
	if start > 0 {
		remaining = append(remaining, region[:start]...)
	}
	if end < len(region) {
		remaining = append(remaining, region[end:]...)
	}
	return header, remaining
}
