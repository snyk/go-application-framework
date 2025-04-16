package code

import (
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/types"
	"github.com/stretchr/testify/assert"
)

const (
	wrapperTestMessageHeader = "Test Security Issue"
	wrapperTestMessageText   = "This is a test security issue"
	wrapperTestComponentName = "test-component"
	wrapperTestScanType      = "sast"
	wrapperTestRuleId        = "test-rule-id"
)

func TestFindingIssueWrapper_Implementation(t *testing.T) {
	// Create a sample finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}

	refId := local_models.TypesReferenceId{
		Identifier: wrapperTestRuleId,
		Index:      0,
	}

	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Create a sample location
	sourceLocation := local_models.IoSnykReactiveFindingSourceLocation{
		Filepath:            "/path/to/file.js",
		OriginalStartLine:   10,
		OriginalEndLine:     10,
		OriginalStartColumn: 5,
		OriginalEndColumn:   20,
	}

	location := local_models.IoSnykReactiveFindingLocation{
		SourceLocations: &sourceLocation,
	}

	// Create a finding resource
	locations := []local_models.IoSnykReactiveFindingLocation{location}
	isAutofixable := false
	finding := local_models.FindingResource{
		Id:   findingId,
		Type: "finding",
		Attributes: local_models.TypesFindingAttributes{
			Locations:     &locations,
			Message:       msg,
			ReferenceId:   &refId,
			Component:     component,
			IsAutofixable: &isAutofixable,
		},
	}

	// Create a sample rule
	rule := local_models.TypesRules{
		Id:   wrapperTestRuleId,
		Name: "Test Rule",
		ShortDescription: struct {
			Text string `json:"text"`
		}{
			Text: "Test Rule Description",
		},
		Properties: struct {
			Categories                []string                             `json:"categories"`
			Cwe                       []string                             `json:"cwe"`
			ExampleCommitDescriptions []string                             `json:"exampleCommitDescriptions"`
			ExampleCommitFixes        []local_models.TypesExampleCommitFix `json:"exampleCommitFixes"`
			Precision                 string                               `json:"precision"`
			RepoDatasetSize           int                                  `json:"repoDatasetSize"`
			Tags                      []string                             `json:"tags"`
		}{
			Cwe: []string{"CWE-79"},
		},
	}

	// Create the wrapper
	wrapper := NewFindingIssueWrapper(finding, &rule, "/project")

	// Test the wrapper methods
	assert.Equal(t, wrapperTestMessageHeader, wrapper.String(), "Expected string representation to match the test message header")
	assert.Equal(t, findingId.String(), wrapper.GetID(), "Expected ID to match the finding ID")
	assert.Equal(t, "/path/to/file.js", string(wrapper.GetAffectedFilePath()), "Expected affected file path to match the test file path")
	assert.Equal(t, wrapperTestMessageText, wrapper.GetMessage(), "Expected message to match the test message text")
	assert.Equal(t, types.CodeSecurityVulnerability, wrapper.GetIssueType(), "Expected issue type to be CodeSecurityVulnerability")
	assert.Equal(t, wrapperTestRuleId, wrapper.GetRuleID(), "Expected rule ID to match the test rule ID")
	assert.Contains(t, wrapper.GetCWEs(), "CWE-79", "Expected CWEs to contain CWE-79")

	// Test the range
	expectedRange := types.Range{
		Start: types.Position{Line: 10, Character: 5},
		End:   types.Position{Line: 10, Character: 20},
	}
	assert.Equal(t, expectedRange, wrapper.GetRange(), "Expected range to match the test range")
}

func TestConvertLocalFindingToIssues(t *testing.T) {
	// Create sample finding and rule
	findingId := uuid.New()
	refId := local_models.TypesReferenceId{
		Identifier: wrapperTestRuleId,
		Index:      0,
	}
	sourceLocation := local_models.IoSnykReactiveFindingSourceLocation{
		Filepath:            "/path/to/file.js",
		OriginalStartLine:   10,
		OriginalEndLine:     10,
		OriginalStartColumn: 5,
		OriginalEndColumn:   20,
	}

	location := local_models.IoSnykReactiveFindingLocation{
		SourceLocations: &sourceLocation,
	}
	locations := []local_models.IoSnykReactiveFindingLocation{location}

	finding := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message: local_models.TypesFindingMessage{
				Header: wrapperTestMessageHeader,
				Text:   wrapperTestMessageText,
			},
			ReferenceId: &refId,
			Locations:   &locations,
		},
	}

	rule := local_models.TypesRules{
		Id:   wrapperTestRuleId,
		Name: "Test Rule",
	}

	// Create a LocalFinding with the sample finding and rule
	localFinding := &local_models.LocalFinding{
		Findings: []local_models.FindingResource{finding},
		Rules:    []local_models.TypesRules{rule},
	}

	// Convert to issues
	issues := ConvertLocalFindingToIssues(localFinding, "/project")

	// Verify conversion
	assert.Len(t, issues, 1, "Expected one issue to be converted")
	assert.Equal(t, findingId.String(), issues[0].GetID(), "Expected ID to match the finding ID")
	assert.Equal(t, wrapperTestRuleId, issues[0].GetRuleID(), "Expected rule ID to match the test rule ID")
	assert.Equal(t, wrapperTestMessageHeader, issues[0].String(), "Expected string representation to match the test message header")
}

func TestFindingIssueWrapper_GetIgnoreDetails(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Case 1: Finding with no suppression
	finding1 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper1 := NewFindingIssueWrapper(finding1, nil, "/project")
	assert.Nil(t, wrapper1.GetIgnoreDetails(), "Expected nil ignore details when no suppression exists")

	// Case 2: Finding with suppression but nil justification
	justification := "This is a test justification"
	suppression := local_models.TypesSuppression{
		Kind: "ignored",
	}
	finding2 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:     msg,
			Component:   component,
			Suppression: &suppression,
		},
	}
	wrapper2 := NewFindingIssueWrapper(finding2, nil, "/project")
	ignoreDetails2 := wrapper2.GetIgnoreDetails()
	assert.NotNil(t, ignoreDetails2, "Expected non-nil ignore details")
	assert.Empty(t, ignoreDetails2.Reason, "Expected empty reason when justification is nil")

	// Case 3: Finding with suppression and non-nil justification
	suppression3 := local_models.TypesSuppression{
		Kind:          "ignored",
		Justification: &justification,
	}
	finding3 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:     msg,
			Component:   component,
			Suppression: &suppression3,
		},
	}
	wrapper3 := NewFindingIssueWrapper(finding3, nil, "/project")
	ignoreDetails3 := wrapper3.GetIgnoreDetails()
	assert.NotNil(t, ignoreDetails3, "Expected non-nil ignore details")
	assert.Equal(t, justification, ignoreDetails3.Reason, "Expected justification to match")
}

func TestFindingIssueWrapper_GetFingerprint(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Case 1: Finding with no fingerprints
	finding1 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper1 := NewFindingIssueWrapper(finding1, nil, "/project")
	assert.Equal(t, findingId.String(), wrapper1.GetFingerprint(), "Expected ID as fallback when no fingerprint exists")
}

func TestFindingIssueWrapper_NilReferenceHandling(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Case 1: Finding with nil locations
	finding1 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper1 := NewFindingIssueWrapper(finding1, nil, "/project")

	// Test GetAffectedFilePath with nil locations
	assert.Equal(t, types.FilePath(""), wrapper1.GetAffectedFilePath(), "Expected empty file path with nil locations")

	// Test GetRange with nil locations
	defaultRange := types.Range{
		Start: types.Position{Line: 1, Character: 1},
		End:   types.Position{Line: 1, Character: 1},
	}
	assert.Equal(t, defaultRange, wrapper1.GetRange(), "Expected default range with nil locations")

	// Case 2: Finding with empty locations array
	emptyLocations := []local_models.IoSnykReactiveFindingLocation{}
	finding2 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
			Locations: &emptyLocations,
		},
	}
	wrapper2 := NewFindingIssueWrapper(finding2, nil, "/project")
	assert.Equal(t, types.FilePath(""), wrapper2.GetAffectedFilePath(), "Expected empty file path with empty locations")

	// Case 3: Finding with location but nil SourceLocations
	location3 := local_models.IoSnykReactiveFindingLocation{}
	locations3 := []local_models.IoSnykReactiveFindingLocation{location3}
	finding3 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
			Locations: &locations3,
		},
	}
	wrapper3 := NewFindingIssueWrapper(finding3, nil, "/project")
	assert.Equal(t, types.FilePath(""), wrapper3.GetAffectedFilePath(), "Expected empty file path with nil SourceLocations")

	// Case 4: Finding with nil ReferenceId
	finding4 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper4 := NewFindingIssueWrapper(finding4, nil, "/project")
	assert.Equal(t, "", wrapper4.GetRuleID(), "Expected empty rule ID with nil ReferenceId")
}

func TestFindingIssueWrapper_UnsupportedFeatures(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Create a finding resource
	finding := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper := NewFindingIssueWrapper(finding, nil, "/project")

	// Test methods that return nil but don't panic
	assert.Nil(t, wrapper.GetReferences(), "Expected nil references")
	assert.Nil(t, wrapper.GetCVEs(), "Expected nil CVEs")
	assert.Nil(t, wrapper.GetIssueDescriptionURL(), "Expected nil issue description URL")
	assert.Equal(t, "", wrapper.GetEcosystem(), "Expected empty ecosystem string")
	assert.Nil(t, wrapper.GetCodeActions(), "Expected nil code actions")
	assert.False(t, wrapper.GetIsNew(), "Expected GetIsNew to return false by default")

	// Test setter methods (should not panic)
	wrapper.SetCodeActions(nil)
	wrapper.SetLessonUrl("https://example.com")
	wrapper.SetGlobalIdentity("test-global-id")
	assert.Equal(t, "https://example.com", wrapper.GetLessonUrl(), "Expected lesson URL to be set")
	assert.Equal(t, "test-global-id", wrapper.GetGlobalIdentity(), "Expected global identity to be set")

	// Test SetIsNew
	wrapper.SetIsNew(true)
	assert.True(t, wrapper.GetIsNew(), "Expected GetIsNew to return true after setting")
}

func TestFindingIssueWrapper_GetSeverity(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Test all possible severity levels
	severityTests := []struct {
		Level            string
		ExpectedSeverity types.Severity
		Description      string
	}{
		{"critical", types.Critical, "Critical severity"},
		{"high", types.High, "High severity"},
		{"medium", types.Medium, "Medium severity"},
		{"low", types.Low, "Low severity"},
		{"info", types.Medium, "Info mapped to Medium severity"},
		{"unknown", types.Medium, "Unknown mapped to Medium severity"},
		{"", types.Medium, "Empty severity mapped to Medium"},
		{"nonsense", types.Medium, "Invalid severity mapped to Medium"},
	}

	for _, test := range severityTests {
		t.Run(test.Description, func(t *testing.T) {
			// Create rating with the test level
			rating := local_models.TypesFindingRating{}

			// Set the severity value directly into the struct
			severityValue := local_models.TypesFindingRatingSeverityValue(test.Level)
			rating.Severity.Value = severityValue

			// Create a finding with this rating
			finding := local_models.FindingResource{
				Id: findingId,
				Attributes: local_models.TypesFindingAttributes{
					Message:   msg,
					Component: component,
					Rating:    &rating,
				},
			}

			// Create the wrapper
			wrapper := NewFindingIssueWrapper(finding, nil, "/project")

			// Test the severity mapping
			assert.Equal(t, test.ExpectedSeverity, wrapper.GetSeverity(),
				"Severity level '%s' did not map to expected severity", test.Level)
		})
	}

	// Test nil rating
	t.Run("Nil rating", func(t *testing.T) {
		finding := local_models.FindingResource{
			Id: findingId,
			Attributes: local_models.TypesFindingAttributes{
				Message:   msg,
				Component: component,
			},
		}
		wrapper := NewFindingIssueWrapper(finding, nil, "/project")
		assert.Equal(t, types.Medium, wrapper.GetSeverity(), "Nil rating should map to Medium severity")
	})
}

func TestFindingIssueWrapper_GetCWEs(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Case 1: Finding with no rule (nil rule)
	finding1 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper1 := NewFindingIssueWrapper(finding1, nil, "/project")
	assert.Empty(t, wrapper1.GetCWEs(), "Expected empty CWEs with nil rule")

	// Case 2: Finding with rule but no CWEs
	rule2 := local_models.TypesRules{
		Id:   wrapperTestRuleId,
		Name: "Test Rule",
		Properties: struct {
			Categories                []string                             `json:"categories"`
			Cwe                       []string                             `json:"cwe"`
			ExampleCommitDescriptions []string                             `json:"exampleCommitDescriptions"`
			ExampleCommitFixes        []local_models.TypesExampleCommitFix `json:"exampleCommitFixes"`
			Precision                 string                               `json:"precision"`
			RepoDatasetSize           int                                  `json:"repoDatasetSize"`
			Tags                      []string                             `json:"tags"`
		}{},
	}
	finding2 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper2 := NewFindingIssueWrapper(finding2, &rule2, "/project")
	assert.Empty(t, wrapper2.GetCWEs(), "Expected empty CWEs with empty rule.Properties.Cwe")

	// Case 3: Finding with rule and multiple CWEs
	rule3 := local_models.TypesRules{
		Id:   wrapperTestRuleId,
		Name: "Test Rule",
		Properties: struct {
			Categories                []string                             `json:"categories"`
			Cwe                       []string                             `json:"cwe"`
			ExampleCommitDescriptions []string                             `json:"exampleCommitDescriptions"`
			ExampleCommitFixes        []local_models.TypesExampleCommitFix `json:"exampleCommitFixes"`
			Precision                 string                               `json:"precision"`
			RepoDatasetSize           int                                  `json:"repoDatasetSize"`
			Tags                      []string                             `json:"tags"`
		}{
			Cwe: []string{"CWE-79", "CWE-22", "CWE-89"},
		},
	}
	finding3 := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper3 := NewFindingIssueWrapper(finding3, &rule3, "/project")

	expectedCWEs := []string{"CWE-79", "CWE-22", "CWE-89"}
	actualCWEs := wrapper3.GetCWEs()
	assert.Equal(t, len(expectedCWEs), len(actualCWEs), "Expected same number of CWEs")
	for i, cwe := range expectedCWEs {
		assert.Equal(t, cwe, actualCWEs[i], "Expected CWE %s at position %d", cwe, i)
	}
}

func TestFindingIssueWrapper_SetMethods(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Create a finding resource
	finding := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}
	wrapper := NewFindingIssueWrapper(finding, nil, "/project")

	// Test Setting Additional Data
	newData := &FindingIssueAdditionalData{
		finding: local_models.FindingResource{
			Attributes: local_models.TypesFindingAttributes{
				ReferenceId: &local_models.TypesReferenceId{
					Identifier: wrapperTestRuleId,
				},
				Message: local_models.TypesFindingMessage{
					Header: "Test Header",
				},
			},
		},
	}
	wrapper.SetAdditionalData(newData)
	actualData := wrapper.GetAdditionalData()
	assert.IsType(t, &FindingIssueAdditionalData{}, actualData, "Expected FindingIssueAdditionalData type")
	assert.Equal(t, wrapperTestRuleId, actualData.(*FindingIssueAdditionalData).GetKey(), "Expected GetKey to return the test ID")
	assert.Equal(t, "Test Header", actualData.(*FindingIssueAdditionalData).GetTitle(), "Expected GetTitle to return the test header")

	// Test SetLessonUrl
	assert.Empty(t, wrapper.GetLessonUrl(), "Expected empty lesson URL initially")
	wrapper.SetLessonUrl("https://example.com/lesson")
	assert.Equal(t, "https://example.com/lesson", wrapper.GetLessonUrl(), "Expected lesson URL to be set")

	// Test SetGlobalIdentity
	assert.Empty(t, wrapper.GetGlobalIdentity(), "Expected empty global identity initially")
	wrapper.SetGlobalIdentity("test-global-id")
	assert.Equal(t, "test-global-id", wrapper.GetGlobalIdentity(), "Expected global identity to be set")

	// Test SetIsNew
	assert.False(t, wrapper.GetIsNew(), "Expected GetIsNew to return false by default")
	wrapper.SetIsNew(true)
	assert.True(t, wrapper.GetIsNew(), "Expected GetIsNew to return true after setting")
}

func TestFindingIssueWrapper_UntestableMethods(t *testing.T) {
	// Create a basic finding resource
	findingId := uuid.New()
	msg := local_models.TypesFindingMessage{
		Header: wrapperTestMessageHeader,
		Text:   wrapperTestMessageText,
	}
	component := local_models.TypesComponent{
		Name:     wrapperTestComponentName,
		ScanType: wrapperTestScanType,
	}

	// Create a finding resource
	finding := local_models.FindingResource{
		Id: findingId,
		Attributes: local_models.TypesFindingAttributes{
			Message:   msg,
			Component: component,
		},
	}

	// Create the wrapper
	wrapper := NewFindingIssueWrapper(finding, nil, "/project")

	// Test GetFormattedMessage (it returns the message text)
	assert.Equal(t, wrapperTestMessageText, wrapper.GetFormattedMessage(), "Expected GetFormattedMessage to return the message text")

	// Test GetIsIgnored (it returns false as not implemented)
	assert.False(t, wrapper.GetIsIgnored(), "Expected GetIsIgnored to return false")

	// Test GetCodelensCommands (it returns nil as not implemented)
	assert.Nil(t, wrapper.GetCodelensCommands(), "Expected GetCodelensCommands to return nil")

	// Test SetCodelensCommands (passing nil as we don't have access to the actual type)
	wrapper.SetCodelensCommands(nil)
	assert.Nil(t, wrapper.GetCodelensCommands(), "Expected GetCodelensCommands to still return nil after setting")

	// Test SetRange (it's a no-op)
	initialRange := wrapper.GetRange()
	newRange := types.Range{
		Start: types.Position{Line: 100, Character: 100},
		End:   types.Position{Line: 200, Character: 200},
	}
	wrapper.SetRange(newRange)
	assert.Equal(t, initialRange, wrapper.GetRange(), "Expected range to remain unchanged after SetRange")
}
