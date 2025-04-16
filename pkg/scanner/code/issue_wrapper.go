// Package code provides a scanner implementation for Snyk Code
package code

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/product"
	"github.com/snyk/go-application-framework/pkg/types"
)

// FindingIssueWrapper implements types.Issue for local_models.FindingResource
type FindingIssueWrapper struct {
	finding     local_models.FindingResource
	rule        *local_models.TypesRules
	lessonUrl   string
	isNew       bool
	commands    []types.CommandData
	codeActions []types.CodeAction
	globalId    string
	filePath    types.FilePath
	systemPath  string
	additional  types.IssueAdditionalData
}

// FindingIssueAdditionalData implements types.IssueAdditionalData for local findings
type FindingIssueAdditionalData struct {
	finding local_models.FindingResource
}

// MarshalJSON implements json.Marshaler
func (a *FindingIssueAdditionalData) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetKey returns a unique key for this data
func (a *FindingIssueAdditionalData) GetKey() string {
	return a.finding.Attributes.ReferenceId.Identifier
}

// GetTitle returns the title of this data
func (a *FindingIssueAdditionalData) GetTitle() string {
	return a.finding.Attributes.Message.Header
}

// IsFixable returns true if this issue can be fixed
func (a *FindingIssueAdditionalData) IsFixable() bool {
	return a.finding.Attributes.IsAutofixable != nil && *a.finding.Attributes.IsAutofixable
}

// GetFilterableIssueType returns the filterable issue type
func (a *FindingIssueAdditionalData) GetFilterableIssueType() product.FilterableIssueType {
	return product.FilterableIssueTypeCodeSecurity
}

// NewFindingIssueWrapper creates a new wrapper that implements types.Issue for a FindingResource
func NewFindingIssueWrapper(finding local_models.FindingResource, rule *local_models.TypesRules, systemPath string) *FindingIssueWrapper {
	// Determine file path by looking at the finding's locations
	filePath := types.FilePath("")
	if finding.Attributes.Locations != nil && len(*finding.Attributes.Locations) > 0 {
		if (*finding.Attributes.Locations)[0].SourceLocations != nil {
			filePath = types.FilePath((*finding.Attributes.Locations)[0].SourceLocations.Filepath)
		}
	}

	return &FindingIssueWrapper{
		finding:    finding,
		rule:       rule,
		filePath:   filePath,
		systemPath: systemPath,
		additional: &FindingIssueAdditionalData{finding: finding},
	}
}

// String returns a string representation of this issue
func (w *FindingIssueWrapper) String() string {
	return w.finding.Attributes.Message.Header
}

// GetID returns a unique identifier for this issue
func (w *FindingIssueWrapper) GetID() string {
	return w.finding.Id.String()
}

// GetRange returns the range of this issue
func (w *FindingIssueWrapper) GetRange() types.Range {
	// Default values
	startLine := 1
	endLine := 1
	startChar := 1
	endChar := 1

	// Extract location information if available
	if w.finding.Attributes.Locations != nil && len(*w.finding.Attributes.Locations) > 0 {
		if (*w.finding.Attributes.Locations)[0].SourceLocations != nil {
			loc := (*w.finding.Attributes.Locations)[0].SourceLocations
			startLine = loc.OriginalStartLine
			endLine = loc.OriginalEndLine
			startChar = loc.OriginalStartColumn
			endChar = loc.OriginalEndColumn
		}
	}

	return types.Range{
		Start: types.Position{
			Line:      startLine,
			Character: startChar,
		},
		End: types.Position{
			Line:      endLine,
			Character: endChar,
		},
	}
}

// GetMessage returns the message of this issue
func (w *FindingIssueWrapper) GetMessage() string {
	return w.finding.Attributes.Message.Text
}

// GetFormattedMessage returns the formatted message of this issue
func (w *FindingIssueWrapper) GetFormattedMessage() string {
	if w.finding.Attributes.Message.Markdown != "" {
		return w.finding.Attributes.Message.Markdown
	}
	return w.finding.Attributes.Message.Text
}

// GetAffectedFilePath returns the file path affected by this issue
func (w *FindingIssueWrapper) GetAffectedFilePath() types.FilePath {
	return w.filePath
}

// GetIsNew returns true if this issue is new
func (w *FindingIssueWrapper) GetIsNew() bool {
	return w.isNew
}

// GetIsIgnored returns true if this issue is ignored
func (w *FindingIssueWrapper) GetIsIgnored() bool {
	return w.finding.Attributes.Suppression != nil
}

// GetSeverity returns the severity of this issue
func (w *FindingIssueWrapper) GetSeverity() types.Severity {
	// Map severity string to types.Severity
	if w.finding.Attributes.Rating != nil {
		severity := strings.ToLower(string(w.finding.Attributes.Rating.Severity.Value))
		switch severity {
		case "critical":
			return types.Critical
		case "high":
			return types.High
		case "medium":
			return types.Medium
		case "low":
			return types.Low
		}
	}

	// Default to medium if not specified
	return types.Medium
}

// GetIgnoreDetails returns details about why this issue is ignored
func (w *FindingIssueWrapper) GetIgnoreDetails() *types.IgnoreDetails {
	if w.finding.Attributes.Suppression == nil {
		return nil
	}

	// Create an IgnoreDetails object with suppression information
	var reason string
	if w.finding.Attributes.Suppression.Justification != nil {
		reason = *w.finding.Attributes.Suppression.Justification
	}

	details := &types.IgnoreDetails{
		Reason: reason,
	}

	return details
}

// GetProduct returns the product this issue comes from
func (w *FindingIssueWrapper) GetProduct() product.Product {
	return product.ProductCode
}

// GetFingerprint returns a fingerprint for this issue
func (w *FindingIssueWrapper) GetFingerprint() string {
	// Use the first fingerprint if available
	if len(w.finding.Attributes.Fingerprint) > 0 {
		// Since Fingerprint is a union type, we need to extract the value differently
		// We can use the ID as a fallback
		return w.GetID()
	}
	return w.GetID()
}

// GetGlobalIdentity returns a global identity for this issue
func (w *FindingIssueWrapper) GetGlobalIdentity() string {
	return w.globalId
}

// GetAdditionalData returns additional data for this issue
func (w *FindingIssueWrapper) GetAdditionalData() types.IssueAdditionalData {
	return w.additional
}

// GetEcosystem returns the ecosystem this issue belongs to
func (w *FindingIssueWrapper) GetEcosystem() string {
	return ""
}

// GetCWEs returns the CWEs associated with this issue
func (w *FindingIssueWrapper) GetCWEs() []string {
	if w.rule != nil {
		return w.rule.Properties.Cwe
	}
	return nil
}

// GetCVEs returns the CVEs associated with this issue
func (w *FindingIssueWrapper) GetCVEs() []string {
	return nil
}

// GetIssueType returns the type of this issue
func (w *FindingIssueWrapper) GetIssueType() types.IssueType {
	return types.CodeSecurityVulnerability
}

// GetLessonUrl returns a URL to a lesson about this issue
func (w *FindingIssueWrapper) GetLessonUrl() string {
	return w.lessonUrl
}

// GetIssueDescriptionURL returns a URL to a description of this issue
func (w *FindingIssueWrapper) GetIssueDescriptionURL() *url.URL {
	return nil
}

// GetCodeActions returns the code actions for this issue
func (w *FindingIssueWrapper) GetCodeActions() []types.CodeAction {
	return w.codeActions
}

// GetCodelensCommands returns the codelens commands for this issue
func (w *FindingIssueWrapper) GetCodelensCommands() []types.CommandData {
	return w.commands
}

// GetFilterableIssueType returns the filterable issue type
func (w *FindingIssueWrapper) GetFilterableIssueType() product.FilterableIssueType {
	return product.FilterableIssueTypeCodeSecurity
}

// GetRuleID returns the rule ID for this issue
func (w *FindingIssueWrapper) GetRuleID() string {
	if w.finding.Attributes.ReferenceId == nil {
		return ""
	}
	return w.finding.Attributes.ReferenceId.Identifier
}

// GetReferences returns references for this issue
func (w *FindingIssueWrapper) GetReferences() []types.Reference {
	return nil
}

// SetCodelensCommands sets the codelens commands for this issue
func (w *FindingIssueWrapper) SetCodelensCommands(lenses []types.CommandData) {
	w.commands = lenses
}

// SetLessonUrl sets the lesson URL for this issue
func (w *FindingIssueWrapper) SetLessonUrl(url string) {
	w.lessonUrl = url
}

// SetAdditionalData sets additional data for this issue
func (w *FindingIssueWrapper) SetAdditionalData(data types.IssueAdditionalData) {
	w.additional = data
}

// SetGlobalIdentity sets the global identity for this issue
func (w *FindingIssueWrapper) SetGlobalIdentity(globalIdentity string) {
	w.globalId = globalIdentity
}

// SetIsNew sets whether this issue is new
func (w *FindingIssueWrapper) SetIsNew(isNew bool) {
	w.isNew = isNew
}

// SetCodeActions sets the code actions for this issue
func (w *FindingIssueWrapper) SetCodeActions(actions []types.CodeAction) {
	w.codeActions = actions
}

// SetRange sets the range for this issue
func (w *FindingIssueWrapper) SetRange(r types.Range) {
	// This is a no-op because we derive the range from the finding's locations
}

// ConvertLocalFindingToIssues converts a LocalFinding to a slice of types.Issue
func ConvertLocalFindingToIssues(localFinding *local_models.LocalFinding, systemPath string) []types.Issue {
	var issues []types.Issue

	// Create a map of rule IDs to rules for quick lookup
	ruleMap := make(map[string]*local_models.TypesRules)
	for i, rule := range localFinding.Rules {
		ruleMap[rule.Id] = &localFinding.Rules[i]
	}

	// Convert each finding to an issue
	for _, finding := range localFinding.Findings {
		// Find the rule for this finding
		rule := ruleMap[finding.Attributes.ReferenceId.Identifier]

		// Create an issue wrapper
		issue := NewFindingIssueWrapper(finding, rule, systemPath)

		// Add to the slice of issues
		issues = append(issues, issue)
	}

	return issues
}
