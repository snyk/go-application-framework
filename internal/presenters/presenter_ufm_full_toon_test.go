package presenters

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectFullTOONDocumentSafeRun(t *testing.T) {
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
				{"id": "A", "help": {"text": "short"}, "other": null, "results": [
					{"locations": null, "resultIndex": 1}
				]},
				{"id": "B", "results": [
					{"message": {"text": "first"}, "resultIndex": 0},
					{"fixes": [], "resultIndex": 2}
				]},
				{"id": "C", "results": []}
			]} }
		}]
	}`)
	require.Equal(t, expected, document)
}

func TestProjectFullTOONDocumentUnsafeRunsStayFlat(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"duplicate rule id": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A"}, {"id": "A"}]}},
			"results": [{"ruleId": "A"}]}]}`,
		"rule has results": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A", "results": null}]}},
			"results": [{"ruleId": "A"}]}]}`,
		"result has resultIndex": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A"}]}},
			"results": [{"ruleId": "A", "resultIndex": null}]}]}`,
		"rule is not object": `{
			"runs": [{"tool": {"driver": {"rules": [null]}},
			"results": [{"ruleId": "A"}]}]}`,
		"rule id is not string": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": 1}]}},
			"results": [{"ruleId": "A"}]}]}`,
		"rule id is absent and markdown is preserved": `{
			"runs": [{"tool": {"driver": {"rules": [{"help": {"markdown": "keep"}}]}},
			"results": [{"ruleId": "A"}]}]}`,
		"result is not object": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A"}]}},
			"results": [null]}]}`,
		"result ruleId is absent": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A"}]}},
			"results": [{}]}]}`,
		"result ruleId is not string": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A"}]}},
			"results": [{"ruleId": 1}]}]}`,
		"result ruleId is unresolved": `{
			"runs": [{"tool": {"driver": {"rules": [{"id": "A"}]}},
			"results": [{"ruleId": "B"}]}]}`,
	}

	for name, input := range tests {
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := mustDecodeFullTOONDocument(t, input)
			expected := mustDecodeFullTOONDocument(t, input)

			projectFullTOONDocument(document)

			require.Equal(t, expected, document)
		})
	}
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
				{"id": "B", "help": {"markdown": "remove unsafe"}},
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
				{"id": "A", "help": {}, "results": [{"value": 1, "resultIndex": 0}]}
			]}}},
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

func TestProjectFullTOONDocumentHasExactInverse(t *testing.T) {
	t.Parallel()

	document := mustDecodeFullTOONDocument(t, `{
		"runs": [
			{"tool": {"driver": {"rules": [
				{"id": "A", "help": {"markdown": "remove", "text": "keep"}},
				{"id": "B", "help": {"markdown": null}}
			]}}, "results": [
				{"ruleId": "B", "message": null},
				{"ruleId": "A", "fixes": null, "suppressions": []},
				{"ruleId": "B", "locations": [{"uri": "one"}, {"uri": "two"}]}
			]},
			{"tool": {"driver": {"rules": [
				{"id": "X", "help": {"markdown": "remove too"}},
				{"id": "Y"}
			]}}, "results": [
				{"ruleId": "Y", "properties": {"present": null}}
			]}
		]
	}`)
	expected := mustDecodeFullTOONDocument(t, `{
		"runs": [
			{"tool": {"driver": {"rules": [
				{"id": "A", "help": {"text": "keep"}},
				{"id": "B", "help": {"markdown": null}}
			]}}, "results": [
				{"ruleId": "B", "message": null},
				{"ruleId": "A", "fixes": null, "suppressions": []},
				{"ruleId": "B", "locations": [{"uri": "one"}, {"uri": "two"}]}
			]},
			{"tool": {"driver": {"rules": [
				{"id": "X", "help": {}},
				{"id": "Y"}
			]}}, "results": [
				{"ruleId": "Y", "properties": {"present": null}}
			]}
		]
	}`)

	projectFullTOONDocument(document)
	restoreFullTOONResults(t, document)

	require.Equal(t, expected, document)
}

func restoreFullTOONResults(t *testing.T, document map[string]any) {
	t.Helper()

	runs, ok := document["runs"].([]any)
	require.True(t, ok)
	for _, runValue := range runs {
		run, ok := runValue.(map[string]any)
		require.True(t, ok)
		tool, ok := run["tool"].(map[string]any)
		require.True(t, ok)
		driver, ok := tool["driver"].(map[string]any)
		require.True(t, ok)
		rules, ok := driver["rules"].([]any)
		require.True(t, ok)

		indexedResults := map[int64]any{}
		for _, ruleValue := range rules {
			rule, ok := ruleValue.(map[string]any)
			require.True(t, ok)
			ruleID, ok := rule["id"].(string)
			require.True(t, ok)
			results, ok := rule["results"].([]any)
			require.True(t, ok)
			delete(rule, "results")
			for _, resultValue := range results {
				result, ok := resultValue.(map[string]any)
				require.True(t, ok)
				resultIndex, ok := result["resultIndex"].(json.Number)
				require.True(t, ok)
				index, err := resultIndex.Int64()
				require.NoError(t, err)
				require.GreaterOrEqual(t, index, int64(0))
				_, duplicate := indexedResults[index]
				require.False(t, duplicate)
				delete(result, "resultIndex")
				result["ruleId"] = ruleID
				indexedResults[index] = result
			}
		}

		results := make([]any, len(indexedResults))
		for index := range results {
			result, found := indexedResults[int64(index)]
			require.True(t, found)
			results[index] = result
		}
		run["results"] = results
	}
}

func mustDecodeFullTOONDocument(t *testing.T, input string) map[string]any {
	t.Helper()

	document, err := decodeFullTOONDocument([]byte(input))
	require.NoError(t, err)
	return document
}
