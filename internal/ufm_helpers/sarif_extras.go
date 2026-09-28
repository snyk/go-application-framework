package ufm_helpers

import "encoding/json"

// Test result metadata keys under which the SARIF transformation stores the
// details UFM has no field for, so the SARIF presenter can render them again.
const (
	MetadataKeyFindingExtras = "finding-extras"
	MetadataKeyCoverage      = "coverage"
)

// FindingExtra holds the SARIF result details of one finding, keyed by finding
// ID under MetadataKeyFindingExtras.
type FindingExtra struct {
	Fingerprints           map[string]string     `json:"fingerprints,omitempty"`
	IsAutofixable          bool                  `json:"isAutofixable,omitempty"`
	Arguments              []string              `json:"arguments,omitempty"`
	Suppression            *SuppressionExtra     `json:"suppression,omitempty"`
	MessageText            string                `json:"messageText,omitempty"`
	MessageMarkdown        string                `json:"messageMarkdown,omitempty"`
	PriorityScoreFactors   []PriorityScoreFactor `json:"priorityScoreFactors,omitempty"`
	PolicyOriginalLevel    string                `json:"policyOriginalLevel,omitempty"`
	PolicySeverity         string                `json:"policySeverity,omitempty"`
	PolicyOriginalSeverity string                `json:"policyOriginalSeverity,omitempty"`
}

type SuppressionExtra struct {
	GUID       string `json:"guid,omitempty"`
	Category   string `json:"category,omitempty"`
	IgnoredBy  string `json:"ignoredBy,omitempty"`
	Email      string `json:"email,omitempty"`
	Expiration string `json:"expiration,omitempty"`
	IgnoredOn  string `json:"ignoredOn,omitempty"`
}

type PriorityScoreFactor struct {
	Label bool   `json:"label"`
	Type  string `json:"type"`
}

// Coverage is one entry of the SARIF run coverage stored under MetadataKeyCoverage.
type Coverage struct {
	Files       int    `json:"files"`
	IsSupported bool   `json:"isSupported"`
	Lang        string `json:"lang"`
	Type        string `json:"type"`
}

// DecodeMetadata converts a metadata value into T. The value is either T itself
// (in memory) or its generic JSON form (after a TestResult JSON round trip).
func DecodeMetadata[T any](value interface{}) (T, error) {
	var decoded T
	if typed, ok := value.(T); ok {
		return typed, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return decoded, err
	}
	err = json.Unmarshal(data, &decoded)
	return decoded, err
}
