package presenters

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

var (
	// guidPropertyLine matches a template line writing any SARIF guid property
	// (guid, correlationGuid, ...).
	guidPropertyLine = regexp.MustCompile(`(?i)"[A-Za-z]*guid"\s*:`)
	// guidVariableAssignment matches the assignment of the variable a guid is printed from.
	guidVariableAssignment = regexp.MustCompile(`\{\{-?\s*\$suppGuid\s*:=`)
)

// A SARIF guid is a long-term identity, so templates must only print what
// suppressionGuid derived. This fails for any guid property written from
// another source, and for a guid variable that does not come from suppressionGuid.
func Test_SarifTemplates_GUIDsOnlyComeFromSuppressionGuid(t *testing.T) {
	templates, err := filepath.Glob("templates/*.sarif.tmpl")
	require.NoError(t, err)
	require.NotEmpty(t, templates)

	guidProperties := 0
	for _, path := range templates {
		content, err := os.ReadFile(path)
		require.NoError(t, err)

		for lineNumber, line := range strings.Split(string(content), "\n") {
			location := func() string { return path + ":" + strconv.Itoa(lineNumber+1) + ": " + line }

			if guidPropertyLine.MatchString(line) {
				guidProperties++
				assert.Contains(t, line, "getQuotedString $suppGuid", "guid must print the derived value: %s", location())
			}
			if guidVariableAssignment.MatchString(line) {
				assert.Contains(t, line, ":= suppressionGuid", "$suppGuid must come from suppressionGuid: %s", location())
			}
			assert.NotContains(t, line, "GetPolicyID", "the policy ID can be a per-test snapshot ID and must not reach SARIF: %s", location())
		}
	}
	assert.Positive(t, guidProperties, "no guid property found in the SARIF templates, the check above is vacuous")
}

func Test_suppressionGuid(t *testing.T) {
	id := uuid.NewString()
	expected := ufm_helpers.StableSARIFGUID(ufm_helpers.KindSuppression, id)
	require.NotEmpty(t, expected)

	assert.Equal(t, expected, suppressionGuid(id))
	assert.Equal(t, expected, suppressionGuid(&id))

	var nilString *string
	empty := ""
	nilUUID := uuid.Nil.String()
	assert.Empty(t, suppressionGuid(nilString))
	assert.Empty(t, suppressionGuid(nil))
	assert.Empty(t, suppressionGuid(""))
	assert.Empty(t, suppressionGuid(&empty))
	assert.Empty(t, suppressionGuid(&nilUUID))
	assert.Empty(t, suppressionGuid(42), "unsupported types are omitted, never stringified")
}

func Test_getIgnoreRuleID(t *testing.T) {
	t.Run("implementation with a rule ID", func(t *testing.T) {
		ruleID := uuid.NewString()

		assert.Equal(t, &ruleID, getIgnoreRuleID(ruleIDDetails{ruleID: &ruleID}))
	})

	t.Run("implementation without a rule ID", func(t *testing.T) {
		assert.Nil(t, getIgnoreRuleID(ruleIDDetails{}))
	})

	t.Run("implementation that does not know rules, e.g. a test double", func(t *testing.T) {
		assert.Nil(t, getIgnoreRuleID(plainDetails{}))
	})

	t.Run("nil details", func(t *testing.T) {
		assert.Nil(t, getIgnoreRuleID(nil))
	})
}

// ruleIDDetails is an IssueIgnoreDetails that also knows its rule ID.
type ruleIDDetails struct {
	testapi.IssueIgnoreDetails
	ruleID *string
}

func (d ruleIDDetails) GetRuleID() *string { return d.ruleID }

// plainDetails is an IssueIgnoreDetails without GetRuleID.
type plainDetails struct {
	testapi.IssueIgnoreDetails
}
