package presenters_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

const (
	// Rule behind the ignore of finding 90b2fe3f... in secrets.reviewed-ignore.testresult.json.
	reviewedIgnoreRuleID = "9a589a14-6ea4-49c5-9fd3-618dc3ebbbd1"
	// Per-test policy snapshot ID of that ignore, which must never reach the SARIF.
	reviewedIgnoreSnapshotID = "90b2fe3f-f811-4447-8f75-e32545d753ea"
)

var guidKeyPattern = regexp.MustCompile(`(?i)guid$`)

// collectGUIDs returns the value of every JSON property whose name ends in "guid".
func collectGUIDs(value any) []string {
	var guids []string
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok && guidKeyPattern.MatchString(key) {
				guids = append(guids, text)
				continue
			}
			guids = append(guids, collectGUIDs(child)...)
		}
	case []any:
		for _, child := range typed {
			guids = append(guids, collectGUIDs(child)...)
		}
	default:
		// scalars hold no properties
	}
	return guids
}

// requireStableGUIDs asserts that every guid in the SARIF is a UUIDv5. This is
// stricter than the SARIF schema (versions 1-5): a forwarded backend UUID of any
// version is not derived from a persistent identity and must fail here.
func requireStableGUIDs(t *testing.T, sarifBytes []byte) []string {
	t.Helper()

	validateSarifData(t, sarifBytes)

	var document any
	require.NoError(t, json.Unmarshal(sarifBytes, &document))

	guids := collectGUIDs(document)
	for _, guid := range guids {
		parsed, err := uuid.Parse(guid)
		require.NoError(t, err, "guid %q is not a UUID", guid)
		assert.Equal(t, uuid.Version(5), parsed.Version(), "guid %q must be derived (UUIDv5), not forwarded", guid)
		assert.Equal(t, uuid.RFC4122, parsed.Variant(), "guid %q has the wrong variant", guid)
	}
	return guids
}

func renderUfmSarifBytes(t *testing.T, testResultBytes []byte) []byte {
	t.Helper()

	testResult, err := ufm.NewSerializableTestResultFromBytes(testResultBytes)
	require.NoError(t, err)

	writer := &bytes.Buffer{}
	presenter := presenters.NewUfmRenderer(testResult, configuration.NewWithOpts(), writer,
		presenters.UfmWithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("test"))))
	require.NoError(t, presenter.RenderTemplate(presenters.ApplicationSarifTemplatesUfm, presenters.ApplicationSarifMimeType))
	return writer.Bytes()
}

// uuidOfVersion builds a syntactically valid UUID with the given version.
func uuidOfVersion(version int) string {
	id := uuid.New()
	id[6] = byte(version<<4) | (id[6] & 0x0f)
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}

// uuidVersions are all UUID versions a backend service could switch to.
var uuidVersions = []int{1, 3, 4, 5, 6, 7, 8}

// Every SARIF the UFM presenter renders from the repository fixtures only contains derived guids.
func Test_SarifGUID_AllUfmFixturesContainOnlyStableGUIDs(t *testing.T) {
	fixtures, err := filepath.Glob("testdata/ufm/*testresult*.json")
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	total := 0
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			testResultBytes, err := os.ReadFile(fixture)
			require.NoError(t, err)

			total += len(requireStableGUIDs(t, renderUfmSarifBytes(t, testResultBytes)))
		})
	}
	assert.Positive(t, total, "the fixtures must exercise at least one guid, otherwise this guard is vacuous")
}

// Test API ignores: the guid is derived from the rule behind the ignore, not from
// the policy snapshot ID, which the Test API mints for every test.
func Test_SarifGUID_UfmIgnoreWithRule(t *testing.T) {
	fixture, err := os.ReadFile("testdata/ufm/secrets.reviewed-ignore.testresult.json")
	require.NoError(t, err)
	require.Contains(t, string(fixture), reviewedIgnoreSnapshotID)
	require.Contains(t, string(fixture), reviewedIgnoreRuleID)

	expected := ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, reviewedIgnoreRuleID)
	require.NotEmpty(t, expected)

	t.Run("derived from the rule ID", func(t *testing.T) {
		output := renderUfmSarifBytes(t, fixture)

		assert.Contains(t, requireStableGUIDs(t, output), expected)
		assert.NotContains(t, string(output), reviewedIgnoreSnapshotID, "the snapshot ID must not be forwarded")
		assert.NotContains(t, string(output), reviewedIgnoreRuleID, "the rule ID itself must not be forwarded")
	})

	// The snapshot ID of an ignore can change with every test; the guid must not follow it.
	for _, version := range uuidVersions {
		t.Run(fmt.Sprintf("independent of a v%d snapshot ID", version), func(t *testing.T) {
			snapshotID := uuidOfVersion(version)
			changed := strings.ReplaceAll(string(fixture), reviewedIgnoreSnapshotID, snapshotID)
			require.NotEqual(t, string(fixture), changed)

			output := renderUfmSarifBytes(t, []byte(changed))

			assert.Contains(t, requireStableGUIDs(t, output), expected)
			assert.NotContains(t, string(output), snapshotID)
		})
	}

	for _, version := range uuidVersions {
		t.Run(fmt.Sprintf("a v%d rule ID is derived, not forwarded", version), func(t *testing.T) {
			ruleID := uuidOfVersion(version)
			changed := strings.ReplaceAll(string(fixture), reviewedIgnoreRuleID, ruleID)

			output := renderUfmSarifBytes(t, []byte(changed))

			assert.Contains(t, requireStableGUIDs(t, output), ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, ruleID))
			assert.NotContains(t, string(output), ruleID)
		})
	}

	t.Run("a different rule gives a different guid", func(t *testing.T) {
		changed := strings.ReplaceAll(string(fixture), reviewedIgnoreRuleID, uuid.NewString())

		guids := requireStableGUIDs(t, renderUfmSarifBytes(t, []byte(changed)))

		assert.NotContains(t, guids, expected)
	})

	t.Run("nil UUID rule omits the guid", func(t *testing.T) {
		changed := strings.ReplaceAll(string(fixture), reviewedIgnoreRuleID, uuid.Nil.String())

		guids := requireStableGUIDs(t, renderUfmSarifBytes(t, []byte(changed)))

		assert.NotContains(t, guids, expected)
		assert.NotContains(t, guids, uuid.Nil.String())
	})
}

// Ignores without a rule (legacy project ignores) have no persistent identity, so they get no guid.
func Test_SarifGUID_UfmIgnoreWithoutRuleHasNoGUID(t *testing.T) {
	fixture, err := os.ReadFile("testdata/ufm/webgoat.ignore.testresult.json")
	require.NoError(t, err)
	// The snapshot of this fixture has an ignore but no rule.
	require.NotContains(t, string(fixture), `"rule"`)
	const snapshotID = "31b96aa6-d218-4e5d-a9d6-d42c12ff6712"
	require.Contains(t, string(fixture), snapshotID)

	output := renderUfmSarifBytes(t, fixture)

	assert.Empty(t, requireStableGUIDs(t, output))
	assert.Contains(t, string(output), `"suppressions"`, "the suppression itself must still be reported")
	assert.NotContains(t, string(output), snapshotID)
}

// Snyk Code/Secrets results converted from SARIF carry the upstream suppression ID.
func Test_SarifGUID_UfmFromSarifInput(t *testing.T) {
	const upstreamID = "bffa1c3c-7d67-4ede-b6d0-7d5208ad041d"

	renderWithSuppressionGUID := func(t *testing.T, guid string) (guids []string, raw string) {
		t.Helper()

		input := loadSarifDoc(t, "testdata/with-ignores.json")
		count := 0
		for resultIndex := range input.Runs[0].Results {
			for suppressionIndex := range input.Runs[0].Results[resultIndex].Suppressions {
				input.Runs[0].Results[resultIndex].Suppressions[suppressionIndex].Guid = guid
				count++
			}
		}
		require.Positive(t, count, "fixture must contain suppressions")

		output, err := json.Marshal(renderUfmSarifFromSarifDoc(t, input))
		require.NoError(t, err)
		return requireStableGUIDs(t, output), string(output)
	}

	t.Run("derived from the upstream ID", func(t *testing.T) {
		guids, raw := renderWithSuppressionGUID(t, upstreamID)

		assert.Contains(t, guids, ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, upstreamID))
		assert.NotContains(t, raw, upstreamID)
	})

	for _, version := range uuidVersions {
		t.Run(fmt.Sprintf("v%d upstream ID is derived, not forwarded", version), func(t *testing.T) {
			upstream := uuidOfVersion(version)

			guids, raw := renderWithSuppressionGUID(t, upstream)

			assert.Contains(t, guids, ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, upstream))
			assert.NotContains(t, raw, upstream)
		})
	}

	t.Run("missing upstream ID omits the guid", func(t *testing.T) {
		guids, _ := renderWithSuppressionGUID(t, "")

		assert.Empty(t, guids)
	})
}

// Local findings (Snyk Code) render the suppression ID of the local finding model.
func Test_SarifGUID_LocalFindings(t *testing.T) {
	render := func(t *testing.T, suppressionID *string) []byte {
		t.Helper()

		input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
		require.NoError(t, err)
		changed := 0
		for index := range input.Findings {
			if input.Findings[index].Attributes.Suppression != nil {
				input.Findings[index].Attributes.Suppression.Id = suppressionID
				changed++
			}
		}
		require.Positive(t, changed, "fixture must contain suppressions")

		writer := &bytes.Buffer{}
		p := presenters.NewLocalFindingsRenderer([]*local_models.LocalFinding{input}, configuration.New(), writer)
		require.NoError(t, p.RenderTemplate(presenters.ApplicationSarifTemplates, presenters.ApplicationSarifMimeType))
		return writer.Bytes()
	}

	t.Run("fixture value is derived", func(t *testing.T) {
		input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
		require.NoError(t, err)
		writer := &bytes.Buffer{}
		p := presenters.NewLocalFindingsRenderer([]*local_models.LocalFinding{input}, configuration.New(), writer)
		require.NoError(t, p.RenderTemplate(presenters.ApplicationSarifTemplates, presenters.ApplicationSarifMimeType))

		guids := requireStableGUIDs(t, writer.Bytes())

		assert.NotEmpty(t, guids)
		assert.NotContains(t, writer.String(), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	})

	for _, version := range uuidVersions {
		t.Run(fmt.Sprintf("v%d suppression ID is derived, not forwarded", version), func(t *testing.T) {
			id := uuidOfVersion(version)

			output := render(t, &id)

			assert.Contains(t, requireStableGUIDs(t, output), ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, id))
			assert.NotContains(t, string(output), id)
		})
	}

	t.Run("missing suppression ID omits the guid", func(t *testing.T) {
		assert.Empty(t, requireStableGUIDs(t, render(t, nil)))

		empty := ""
		assert.Empty(t, requireStableGUIDs(t, render(t, &empty)))
	})
}
