package logsummary

import "sort"

type Section int

const (
	SectionPreamble Section = iota
	SectionHeader
	SectionBody
	SectionSummary
	SectionResult
)

type Landmark struct {
	Token Token
	Index int
}

type LandmarkRule struct {
	AnchorToken  Token
	OpensSection Section
}

func findLandmarks(tokens []TokenizedLine, rules []LandmarkRule) []Landmark {
	anchorSet := make(map[Token]struct{}, len(rules))
	for _, r := range rules {
		anchorSet[r.AnchorToken] = struct{}{}
	}
	var landmarks []Landmark
	for i, tok := range tokens {
		if _, ok := anchorSet[tok.Token]; ok {
			landmarks = append(landmarks, Landmark{Token: tok.Token, Index: i})
		}
	}
	return landmarks
}

func splitByLandmarks(tokens []TokenizedLine, landmarks []Landmark, rules []LandmarkRule) map[Section][]TokenizedLine {
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

func extractHeaderFromRegion(region []TokenizedLine) (header, rest []TokenizedLine) {
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

	// Trim trailing blank lines from header
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
