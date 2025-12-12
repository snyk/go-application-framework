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
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils"
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

func renderSeverityColor(input string) string {
	upperInput := strings.ToUpper(input)
	var style lipgloss.TerminalColor
	switch {
	case strings.Contains(upperInput, "CRITICAL"):
		// Purple
		style = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}
	case strings.Contains(upperInput, "HIGH"):
		// Red
		style = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	case strings.Contains(upperInput, "MEDIUM"):
		// Yellow/Orange
		style = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	default:
		style = lipgloss.NoColor{}
	}
	severityStyle := lipgloss.NewStyle().Foreground(style)
	return severityStyle.Render(input)
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
	// SeverityToSarifLevel is for local_models types (local_finding.sarif.tmpl)
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
	// severityToSarifLevel is for string types (ufm.sarif.tmpl)
	fnMap["severityToSarifLevel"] = sarif.SeverityToSarifLevel
	// SARIF building functions
	fnMap["buildRuleShortDescription"] = sarif.BuildRuleShortDescription
	fnMap["buildRuleFullDescription"] = sarif.BuildRuleFullDescription
	fnMap["buildRuleHelpMarkdown"] = sarif.BuildHelpMarkdown
	fnMap["buildRuleTags"] = sarif.BuildRuleTags
	fnMap["getRuleCVSSScore"] = sarif.GetRuleCVSSScore
	fnMap["buildLocationFromIssue"] = sarif.BuildLocation
	fnMap["buildFixesFromIssue"] = sarif.BuildFixesFromIssue
	fnMap["formatIssueMessage"] = sarif.FormatIssueMessage
	return fnMap
}

func getCliTemplateFuncMap(tmpl *template.Template) template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["box"] = func(s string) string { return boxStyle.Render(s) }
	fnMap["toUpperCase"] = strings.ToUpper
	fnMap["toLowerCase"] = strings.ToLower
	fnMap["list"] = func(args ...testapi.FindingType) []testapi.FindingType { return args }
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
	defaultMap["int"] = toInt
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
	defaultMap["getIssuesFromTestResult"] = func(testResults testapi.TestResult, findingType ...testapi.FindingType) []testapi.Issue {
		return utils.ValueOf(testapi.GetIssuesFromTestResult(testResults, findingType))
	}
	defaultMap["getData"] = func(issue testapi.Issue, key string) interface{} {
		value, found := issue.GetData(key)
		if !found {
			return nil
		}
		return value
	}
	defaultMap["convertTypeToIssueName"] = convertTypeToIssueName
	defaultMap["sortAndFilterIssues"] = sortAndFilterIssues(config)
	defaultMap["determineProductNameFromFindingTypes"] = determineProductNameFromFindingTypes
	defaultMap["getSeverities"] = func() []string {
		return json_schemas.DEFAULT_SEVERITIES
	}
	defaultMap["getSummariesFromIssues"] = testapi.GetSummariesFromIssues
	defaultMap["getSortedIssuesFromSummary"] = func(summary *testapi.IssueSummary) []testapi.Issue {
		if summary == nil {
			return []testapi.Issue{}
		}
		sorting := FilterSeverityASC(json_schemas.DEFAULT_SEVERITIES, config.GetString(configuration.FLAG_SEVERITY_THRESHOLD))
		return summary.GetSortedIssues(sorting)
	}

	return defaultMap
}

func convertTypeToIssueName(findingType testapi.FindingType) string {
	// Map backend finding types to human-friendly issue group names
	switch findingType {
	case testapi.FindingTypeSca:
		return "Security"
	case testapi.FindingTypeLicense:
		return "License"
	case testapi.FindingTypeSast:
		return "Code"
	case testapi.FindingTypeDast:
		return "DAST"
	case testapi.FindingTypeSecret:
		return "Secrets"
	default:
		return string(findingType)
	}
}

func sortAndFilterIssues(config configuration.Configuration) func(issues []testapi.Issue, isActive bool) []testapi.Issue {
	return func(issues []testapi.Issue, isActive bool) []testapi.Issue {
		sorting := FilterSeverityASC(json_schemas.DEFAULT_SEVERITIES, config.GetString(configuration.FLAG_SEVERITY_THRESHOLD))

		var filteredIssues []testapi.Issue
		for _, severity := range sorting {
			for _, issue := range issues {
				ignoreDetails := issue.GetIgnoreDetails()
				hasActiveIgnore := ignoreDetails != nil && ignoreDetails.IsActive()

				if hasActiveIgnore == isActive && issue.GetEffectiveSeverity() == severity {
					filteredIssues = append(filteredIssues, issue)
				}
			}
		}
		return filteredIssues
	}
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	case float32:
		return int(val)
	case string:
		// Try to parse string as int
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return 0
}

func determineProductNameFromFindingTypes(findingTypes []testapi.FindingType) string {
	if slices.Contains(findingTypes, testapi.FindingTypeSca) || slices.Contains(findingTypes, testapi.FindingTypeLicense) {
		return "Software Composition Analysis"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeSast) {
		return "Static Code Analysis"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeSecret) {
		return "Secret Detection"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeDast) {
		return "Dynamic Application Security Testing"
	}

	return "Other"
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

	// todo: this is potentially an expensive intermediate conversion to issues, which we could cache or optimize differently.
	issues, err := testapi.NewIssuesFromTestResult(context.Background(), testResults)
	if err != nil {
		return []testapi.FindingType{}
	}

	for _, i := range issues {
		t := i.GetFindingType()
		if _, ok := findingTypes[t]; ok {
			continue
		}
		findingTypes[t] = true
	}

	findingTypesList := slices.Collect(maps.Keys(findingTypes))
	if len(findingTypesList) == 0 {
		return []testapi.FindingType{"no findings type found"}
	}

	return findingTypesList
}
