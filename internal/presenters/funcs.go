package presenters

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/sarif"
)

func add(a, b int) int {
	return a + b
}

func sub(a, b int) int {
	return a - b
}

func hasField(path string) func(obj any) bool {
	return func(obj any) bool {
		// Split the path into fields
		fields := strings.Split(path, ".")

		value := reflect.ValueOf(obj)
		for _, field := range fields {
			// Dereference pointers if necessary
			if value.Kind() == reflect.Ptr {
				value = value.Elem()
			}

			// Ensure the current value is a struct
			if value.Kind() != reflect.Struct {
				return false
			}

			// Retrieve the struct field by name
			value = value.FieldByName(field)
			if !value.IsValid() {
				return false
			}
		}

		// Return true if field value exists
		return value.Interface() != nil
	}
}

// getFieldValueFrom retrieves a value from a struct by a dot-separated path.
func getFieldValueFrom(data interface{}, path string) string {
	// Split the path into fields
	fields := strings.Split(path, ".")
	value := reflect.ValueOf(data)
	for _, field := range fields {
		// Dereference pointers if necessary
		if value.Kind() == reflect.Ptr {
			value = value.Elem()
		}

		// Ensure the current value is a struct
		if value.Kind() != reflect.Struct {
			return ""
		}

		// Retrieve the struct field by name
		value = value.FieldByName(field)
		if !value.IsValid() {
			return ""
		}
	}

	// Return the final field value
	return value.String()
}

// fieldEquals checks if a field value equals a given expected value
func fieldEquals(path string, expectedValue any) func(obj any) bool {
	return func(obj any) bool {
		actualValue := getFieldValueFrom(obj, path)
		return actualValue == expectedValue
	}
}

func getFromConfig(config configuration.Configuration) func(key string) string {
	return func(key string) string {
		if config.GetBool(key) {
			return "true"
		}
		return config.GetString(key)
	}
}

func renderTemplateToString(tmpl *template.Template) func(name string, data interface{}) (string, error) {
	return func(name string, data interface{}) (string, error) {
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, name, data)
		if err != nil {
			return "", err
		}
		return buf.String(), nil
	}
}

func renderSeverityColor(severity string) string {
	var style lipgloss.TerminalColor = lipgloss.NoColor{}
	if strings.Contains(severity, "MEDIUM") {
		style = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	}
	if strings.Contains(severity, "HIGH") {
		style = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	}
	severityStyle := lipgloss.NewStyle().Foreground(style)
	return severityStyle.Render(severity)
}

func sortFindingBy(path string, order []string, findings []local_models.FindingResource) []local_models.FindingResource {
	result := make([]local_models.FindingResource, 0, len(findings))
	result = append(result, findings...)

	slices.SortFunc(result, func(a, b local_models.FindingResource) int {
		aVal := getFieldValueFrom(a, path)
		bVal := getFieldValueFrom(b, path)
		if aVal != bVal {
			return slices.Index(order, aVal) - slices.Index(order, bVal)
		}

		return 0
	})

	return result
}

// filteredFinding takes a filter function and applies it to a list of findings, it will return findings that match the filter function
func filterFinding(cmpFunc func(any) bool, findings []local_models.FindingResource) (filteredFindings []local_models.FindingResource) {
	for _, finding := range findings {
		if cmpFunc(finding) {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	return filteredFindings
}

// filteredFindingsOr applies multiple filter functions to findings, any findings that match any filter will be added to the filteredFindings,
// maintaining the original order.
func filterFindingsOr(findings []local_models.FindingResource, cmpFuncs ...func(any) bool) (filteredFindings []local_models.FindingResource) {
	filteredFindings = make([]local_models.FindingResource, 0)
	addedFindings := make(map[string]bool)

	for _, finding := range findings {
		var fingerprintValue string
		findingAlreadyAdded := false

		// would be nice to use the finding ID, but this is not being sent currently
		// e.g. `filteredFindingsMap[finding.Id.String()] = finding`
		// so we use the "snyk/asset/finding/v1" fingerprint, which may limit the effective scope of this method
		for _, fpUnion := range finding.Attributes.Fingerprint {
			actualFpInterface := getUnionValue(fpUnion)

			if assetFp, ok := actualFpInterface.(local_models.TypesCodeSastFingerprintAssetV1); ok {
				fingerprintValue = assetFp.Value
				findingAlreadyAdded = true
				break
			}
		}

		// avoid adding duplicate findings
		if findingAlreadyAdded && fingerprintValue != "" && addedFindings[fingerprintValue] {
			continue
		}

		// apply filters
		for _, cmpFunc := range cmpFuncs {
			// add filtered findings
			if cmpFunc(finding) {
				filteredFindings = append(filteredFindings, finding)
				if findingAlreadyAdded && fingerprintValue != "" {
					addedFindings[fingerprintValue] = true
				}
				break
			}
		}
	}

	return filteredFindings
}

func isOpenFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(local_models.FindingResource)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression == nil || finding.Attributes.Suppression.Status == local_models.Rejected
	}
}

func isPendingFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(local_models.FindingResource)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression != nil && finding.Attributes.Suppression.Status == local_models.UnderReview
	}
}

func isIgnoredFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(local_models.FindingResource)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression != nil && finding.Attributes.Suppression.Status == local_models.Accepted
	}
}

func hasSuppression(finding local_models.FindingResource) bool {
	if finding.Attributes.Suppression == nil {
		return false
	}

	return finding.Attributes.Suppression.Status != local_models.Rejected
}

func getSarifTemplateFuncMap() template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["SeverityToSarifLevel"] = func(s local_models.TypesFindingRatingSeverityValue) string {
		return sarif.SeverityToSarifLevel(string(s))
	}
	fnMap["getAutomationDetailsId"] = func(projectName string, testType string) string {
		driverName := sarif.ConvertTypeToDriverName(testType)
		driverName = strings.TrimSpace(strings.Replace(driverName, "Snyk", "", 1))

		if projectName != "" {
			projectName = projectName + "/"
		}
		return fmt.Sprintf("Snyk/%s/%s%s", driverName, projectName, time.Now().UTC().Format(time.RFC3339))
	}
	fnMap["convertTypeToDriverName"] = sarif.ConvertTypeToDriverName
	fnMap["getIssuesFromTestResult"] = getIssuesFromTestResult
	fnMap["severityToSarifLevel"] = func(severity string) string {
		return sarif.SeverityToSarifLevel(severity)
	}
	// Result helper functions
	fnMap["buildLocationFromIssue"] = buildLocationFromIssue
	fnMap["buildFixesFromIssue"] = buildFixesFromIssue
	fnMap["formatIssueMessage"] = formatIssueMessage
	// Rule helper functions
	fnMap["buildRuleShortDescription"] = buildRuleShortDescription
	fnMap["buildRuleFullDescription"] = buildRuleFullDescription
	fnMap["buildRuleHelpMarkdown"] = buildRuleHelpMarkdown
	fnMap["buildRuleTags"] = buildRuleTags
	fnMap["getRuleCVSSScore"] = getRuleCVSSScore
	return fnMap
}

func getCliTemplateFuncMap(tmpl *template.Template) template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["box"] = func(s string) string { return boxStyle.Render(s) }
	fnMap["toUpperCase"] = strings.ToUpper
	fnMap["renderInSeverityColor"] = renderSeverityColor
	fnMap["bold"] = renderBold
	fnMap["tip"] = func(s string) string {
		return RenderTip(s + "\n")
	}
	fnMap["divider"] = RenderDivider
	fnMap["title"] = RenderTitle
	fnMap["renderToString"] = renderTemplateToString(tmpl)
	fnMap["isOpenFinding"] = isOpenFinding
	fnMap["isPendingFinding"] = isPendingFinding
	fnMap["isIgnoredFinding"] = isIgnoredFinding
	fnMap["hasSuppression"] = hasSuppression
	return fnMap
}

func getUnionValue(input interface{}) interface{} {
	u, ok := input.(local_models.UnionInterface)
	if !ok {
		return ""
	}

	result, err := u.ValueByDiscriminator()
	if err != nil {
		return ""
	}

	return result
}

func getDefaultTemplateFuncMap(config configuration.Configuration, ri runtimeinfo.RuntimeInfo) template.FuncMap {
	defaultMap := template.FuncMap{}
	defaultMap["getRuntimeInfo"] = func(key string) string { return getRuntimeInfo(key, ri) }
	defaultMap["getValueFromConfig"] = getFromConfig(config)
	defaultMap["sortFindingBy"] = sortFindingBy
	defaultMap["getFieldValueFrom"] = getFieldValueFrom
	defaultMap["fieldEquals"] = fieldEquals
	defaultMap["filterFinding"] = filterFinding
	defaultMap["filterFindingsOr"] = filterFindingsOr
	defaultMap["hasField"] = hasField
	defaultMap["notHasField"] = func(path string) func(obj any) bool {
		return func(obj any) bool {
			return !hasField(path)(obj)
		}
	}
	defaultMap["add"] = add
	defaultMap["sub"] = sub
	defaultMap["reverse"] = reverse
	defaultMap["join"] = strings.Join
	defaultMap["formatDatetime"] = formatDatetime
	defaultMap["getUnionValue"] = getUnionValue
	defaultMap["hasPrefix"] = strings.HasPrefix
	defaultMap["getQuotedString"] = func(input string) string {
		return strconv.Quote(input)
	}
	defaultMap["replaceString"] = func(str string, old string, replaceWith string) string {
		return strings.ReplaceAll(str, old, replaceWith)
	}
	defaultMap["getFindingTypesFromTestResult"] = getFindingTypesFromTestResult
	defaultMap["getFindingsFromTestResult"] = getFindingsFromTestResult

	return defaultMap
}

func reverse(v interface{}) []interface{} {
	l, err := mustReverse(v)
	if err != nil {
		panic(err)
	}

	return l
}

func mustReverse(v interface{}) ([]interface{}, error) {
	tp := reflect.TypeOf(v).Kind()
	switch tp {
	case reflect.Slice, reflect.Array:
		l2 := reflect.ValueOf(v)

		l := l2.Len()
		// We do not sort in place because the incoming array should not be altered.
		nl := make([]interface{}, l)
		for i := 0; i < l; i++ {
			nl[l-i-1] = l2.Index(i).Interface()
		}

		return nl, nil
	default:
		return nil, fmt.Errorf("Cannot find reverse on type %s", tp)
	}
}

func getRuntimeInfo(key string, ri runtimeinfo.RuntimeInfo) string {
	if ri == nil {
		return ""
	}

	switch strings.ToLower(key) {
	case "name":
		return ri.GetName()
	case "version":
		return ri.GetVersion()
	default:
		return ""
	}
}

func formatDatetime(input string, inputFormat string, outputFormat string) string {
	datetime, err := time.Parse(inputFormat, input)
	if err != nil {
		return input
	}

	return datetime.Format(outputFormat)
}

func getFindingTypesFromTestResult(testResults testapi.TestResult) []testapi.FindingType {
	findingTypes := map[testapi.FindingType]bool{}
	findings, _, err := testResults.Findings(context.Background())
	if err != nil {
		return []testapi.FindingType{}
	}

	for _, findings := range findings {
		if _, ok := findingTypes[findings.Attributes.FindingType]; ok {
			continue
		}
		findingTypes[findings.Attributes.FindingType] = true
	}
	return slices.Collect(maps.Keys(findingTypes))
}

func getFindingsFromTestResult(testResults testapi.TestResult) []testapi.FindingData {
	findings, _, err := testResults.Findings(context.Background())
	if err != nil {
		return []testapi.FindingData{}
	}
	return findings
}

// getIssuesFromTestResult converts test results to Issues and filters by finding type
func getIssuesFromTestResult(testResults testapi.TestResult, findingType testapi.FindingType) []testapi.Issue {
	ctx := context.Background()
	issuesList, err := testapi.NewIssuesFromTestResult(ctx, testResults)
	if err != nil {
		return []testapi.Issue{}
	}

	// Filter issues by finding type
	var filteredIssues []testapi.Issue
	for _, issue := range issuesList {
		if issue.GetFindingType() == findingType {
			filteredIssues = append(filteredIssues, issue)
		}
	}

	// Sort by ID for deterministic output
	slices.SortFunc(filteredIssues, func(a, b testapi.Issue) int {
		return strings.Compare(a.GetID(), b.GetID())
	})

	return filteredIssues
}

// formatIssueMessage creates the SARIF message text for an issue
func formatIssueMessage(issue testapi.Issue) string {
	componentName, _ := issue.GetMetadata(testapi.MetadataKeyComponentName)
	componentNameStr := fmt.Sprintf("%v", componentName)
	if componentNameStr == "" || componentNameStr == "<nil>" {
		componentNameStr = "package"
	}
	return fmt.Sprintf("This file introduces a vulnerable %s package with a %s severity vulnerability.",
		componentNameStr, issue.GetSeverity())
}

// buildLocationFromIssue builds SARIF location from issue
// Delegates to sarif.BuildLocation for the actual implementation
func buildLocationFromIssue(issue testapi.Issue) map[string]interface{} {
	findings := issue.GetFindings()
	if len(findings) == 0 {
		return nil
	}

	// Use the existing buildLocation logic from sarif package
	return sarif.BuildLocation(findings[0], issue)
}

// buildFixesFromIssue builds SARIF fixes array from issue
// Matches the logic in sarif.addFixesIfAvailable - checks metadata first
func buildFixesFromIssue(issue testapi.Issue) []interface{} {
	findings := issue.GetFindings()
	if len(findings) == 0 {
		return nil
	}

	// Check metadata to determine if fixes should be shown (matches old behavior)
	isFixable, ok := issue.GetMetadata(testapi.MetadataKeyIsFixable)
	if !ok {
		return nil
	}
	isFixableBool, ok := isFixable.(bool)
	if !ok || !isFixableBool {
		return nil
	}

	fixedVersionsVal, ok := issue.GetMetadata(testapi.MetadataKeyFixedInVersions)
	if !ok {
		return nil
	}
	fixedVersions, ok := fixedVersionsVal.([]string)
	if !ok || len(fixedVersions) == 0 {
		return nil
	}

	// Use the existing buildFixes logic from sarif package
	return sarif.BuildFixes(findings[0], issue)
}

// buildRuleShortDescription creates the short description for a SARIF rule
func buildRuleShortDescription(issue testapi.Issue) string {
	componentName, _ := issue.GetMetadata(testapi.MetadataKeyComponentName)
	componentNameStr := fmt.Sprintf("%v", componentName)
	if componentNameStr == "" || componentNameStr == "<nil>" {
		componentNameStr = "package"
	}
	severity := issue.GetSeverity()
	title := issue.GetTitle()

	// Capitalize first letter of severity
	if len(severity) > 0 {
		severity = strings.ToUpper(severity[:1]) + severity[1:]
	}

	return fmt.Sprintf("%s severity - %s vulnerability in %s", severity, title, componentNameStr)
}

// buildRuleFullDescription creates the full description for a SARIF rule
func buildRuleFullDescription(issue testapi.Issue) string {
	componentName, _ := issue.GetMetadata(testapi.MetadataKeyComponentName)
	componentVersion, _ := issue.GetMetadata(testapi.MetadataKeyComponentVersion)

	componentNameStr := fmt.Sprintf("%v", componentName)
	componentVersionStr := fmt.Sprintf("%v", componentVersion)

	fullDesc := fmt.Sprintf("%s@%s", componentNameStr, componentVersionStr)
	cveIds := issue.GetCVEs()
	if len(cveIds) > 0 {
		fullDesc = fmt.Sprintf("(%s) %s", strings.Join(cveIds, ", "), fullDesc)
	}
	return fullDesc
}

// buildRuleHelpMarkdown creates the help markdown for a SARIF rule
func buildRuleHelpMarkdown(issue testapi.Issue, findingType testapi.FindingType) string {
	return sarif.BuildHelpMarkdown(issue, findingType)
}

// buildRuleTags creates the tags array for a SARIF rule
func buildRuleTags(issue testapi.Issue) []interface{} {
	tags := []interface{}{"security"}
	for _, cwe := range issue.GetCWEs() {
		tags = append(tags, cwe)
	}

	technology, ok := issue.GetMetadata(testapi.MetadataKeyTechnology)
	if ok {
		if techStr, ok := technology.(string); ok && techStr != "" {
			tags = append(tags, techStr)
		}
	}

	return tags
}

// getRuleCVSSScore extracts the CVSS score from issue metadata
func getRuleCVSSScore(issue testapi.Issue) float32 {
	cvssScore, ok := issue.GetMetadata(testapi.MetadataKeyCVSSScore)
	if !ok {
		return 0.0
	}
	if score, ok := cvssScore.(float32); ok {
		return score
	}
	return 0.0
}
