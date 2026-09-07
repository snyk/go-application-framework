package presenters_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

// These fixtures define the JSON input to the future TOON presenter.
// See testdata/ufm/toon/README.md for reference TOON commands.
func Test_UfmTOONContract(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "ufm", "toon")
	matches, err := filepath.Glob(filepath.Join(fixtureDir, "*.testresult.json"))
	require.NoError(t, err)
	require.NotEmpty(t, matches, "no contract fixtures found")
	sort.Strings(matches)

	for _, inputPath := range matches {
		name := strings.TrimSuffix(filepath.Base(inputPath), ".testresult.json")
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(inputPath)
			require.NoError(t, err)
			results, err := ufm.NewSerializableTestResultFromBytes(input)
			require.NoError(t, err)

			envelope := make([]map[string]any, 0, len(results))
			for _, result := range results {
				findings, complete, findingsErr := result.Findings(t.Context())
				require.NoError(t, findingsErr)
				require.True(t, complete, "incomplete findings cannot define a successful golden")
				if findings == nil {
					findings = []testapi.FindingData{}
				}
				envelope = append(envelope, map[string]any{
					"testId":            result.GetTestID(),
					"testConfiguration": result.GetTestConfiguration(),
					"testSubject":       result.Get(testapi.TestResultTestSubject),
					"executionState":    result.GetExecutionState(),
					"passFail":          result.GetPassFail(),
					"outcomeReason":     result.GetOutcomeReason(),
					"errors":            result.GetErrors(),
					"warnings":          result.GetWarnings(),
					"rawSummary":        result.Get(testapi.TestResultRawSummary),
					"effectiveSummary":  result.GetEffectiveSummary(),
					"findings":          findings,
				})
			}
			actual, err := json.Marshal(map[string]any{"results": envelope})
			require.NoError(t, err)
			expected, err := os.ReadFile(filepath.Join(fixtureDir, name+".json"))
			require.NoError(t, err)
			require.Equal(t, decodeTOONContractJSON(t, expected), decodeTOONContractJSON(t, actual))
		})
	}
}

func decodeTOONContractJSON(t *testing.T, data []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	require.NoError(t, decoder.Decode(&value))
	return value
}
