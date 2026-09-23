package presenters

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectFullTOONDocumentPreservesFlatResultsAndRuleIDs(t *testing.T) {
	t.Parallel()

	document := mustDecodeFullTOONDocument(t, `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "long", "text": "short"}, "other": null},
				{"id": "B"},
				{"id": "C"}
			]}},
			"results": [
				{"ruleId": "B", "message": {"text": "first"}},
				{"ruleId": "A", "locations": null},
				{"ruleId": "B", "fixes": []}
			]
		}]
	}`)

	projectFullTOONDocument(document)

	expected := mustDecodeFullTOONDocument(t, `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "A", "help": {"text": "short"}, "other": null},
				{"id": "B"},
				{"id": "C"}
			]}},
			"results": [
				{"ruleId": "B", "message": {"text": "first"}},
				{"ruleId": "A", "locations": null},
				{"ruleId": "B", "fixes": []}
			]
		}]
	}`)
	require.Equal(t, expected, document)
}

func TestProjectFullTOONDocumentDeletesOnlyEligibleMarkdown(t *testing.T) {
	t.Parallel()

	document := mustDecodeFullTOONDocument(t, `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "remove", "text": "keep", "other": null}},
				{"id": "", "help": {"markdown": "remove empty id"}},
				{"id": "B", "help": {"markdown": null}},
				{"id": "C", "help": {"markdown": 1}},
				{"id": 1, "help": {"markdown": "keep invalid id"}},
				{"id": "D", "help": "keep malformed help"},
				null
			]}},
			"results": []
		}]
	}`)

	projectFullTOONDocument(document)

	expected := mustDecodeFullTOONDocument(t, `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "A", "help": {"text": "keep", "other": null}},
				{"id": "", "help": {}},
				{"id": "B", "help": {"markdown": null}},
				{"id": "C", "help": {"markdown": 1}},
				{"id": 1, "help": {"markdown": "keep invalid id"}},
				{"id": "D", "help": "keep malformed help"},
				null
			]}},
			"results": []
		}]
	}`)
	require.Equal(t, expected, document)
}

func TestProjectFullTOONDocumentPreservesAbsentNullAndEmptyResults(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input    string
		expected string
	}{
		"absent": {
			input: `{"runs": [{"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "remove"}}
			]}}}]}`,
			expected: `{"runs": [{"tool": {"driver": {"rules": [
				{"id": "A", "help": {}}
			]}}}]}`,
		},
		"null": {
			input: `{"runs": [{"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "remove"}}
			]}}, "results": null}]}`,
			expected: `{"runs": [{"tool": {"driver": {"rules": [
				{"id": "A", "help": {}}
			]}}, "results": null}]}`,
		},
		"empty": {
			input: `{"runs": [{"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "remove"}}
			]}}, "results": []}]}`,
			expected: `{"runs": [{"tool": {"driver": {"rules": [
				{"id": "A", "help": {}}
			]}}, "results": []}]}`,
		},
		"rules absent": {
			input:    `{"runs": [{"tool": {"driver": {}}, "results": [{"ruleId": "A"}]}]}`,
			expected: `{"runs": [{"tool": {"driver": {}}, "results": [{"ruleId": "A"}]}]}`,
		},
		"rules null": {
			input:    `{"runs": [{"tool": {"driver": {"rules": null}}, "results": [{"ruleId": "A"}]}]}`,
			expected: `{"runs": [{"tool": {"driver": {"rules": null}}, "results": [{"ruleId": "A"}]}]}`,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := mustDecodeFullTOONDocument(t, test.input)

			projectFullTOONDocument(document)

			require.Equal(t, mustDecodeFullTOONDocument(t, test.expected), document)
		})
	}
}

func TestProjectFullTOONDocumentHandlesRunsIndependently(t *testing.T) {
	t.Parallel()

	document := mustDecodeFullTOONDocument(t, `{
		"runs": [
			{"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "remove safe"}}
			]}}, "results": [{"ruleId": "A", "value": 1}]},
			{"tool": {"driver": {"rules": [
				{"id": "B", "help": {"markdown": "remove duplicate"}},
				{"id": "B"}
			]}}, "results": [{"ruleId": "B", "value": 2}]},
			{"tool": {"driver": {"rules": [
				{"id": "C", "help": {"markdown": "remove empty"}}
			]}}, "results": []}
		]
	}`)

	projectFullTOONDocument(document)

	expected := mustDecodeFullTOONDocument(t, `{
		"runs": [
			{"tool": {"driver": {"rules": [
				{"id": "A", "help": {}}
			]}}, "results": [{"ruleId": "A", "value": 1}]},
			{"tool": {"driver": {"rules": [
				{"id": "B", "help": {}},
				{"id": "B"}
			]}}, "results": [{"ruleId": "B", "value": 2}]},
			{"tool": {"driver": {"rules": [
				{"id": "C", "help": {}}
			]}}, "results": []}
		]
	}`)
	require.Equal(t, expected, document)
}

func mustDecodeFullTOONDocument(t *testing.T, input string) map[string]any {
	t.Helper()

	document, err := decodeFullTOONDocument([]byte(input))
	require.NoError(t, err)
	return document
}
