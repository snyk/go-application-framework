package presenters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	htmlTemplate "html/template"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/utils/sarif"
	"github.com/snyk/go-application-framework/pkg/utils/target"
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
	return severityStyle.Render(upperInput)
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

func getExecutionFlowsFromIssue(issue testapi.Issue) []testapi.ExecutionFlowEvidence {
	var flows []testapi.ExecutionFlowEvidence
	for _, finding := range issue.GetFindings() {
		if finding.Attributes == nil {
			continue
		}
		for _, ev := range finding.Attributes.Evidence {
			discriminator, err := ev.Discriminator()
			if err != nil || discriminator != "execution_flow" {
				continue
			}
			execFlow, err := ev.AsExecutionFlowEvidence()
			if err == nil {
				flows = append(flows, execFlow)
			}
		}
	}
	return flows
}

func getPolicyModificationsFromIssue(issue testapi.Issue) []testapi.PolicyModification {
	for _, finding := range issue.GetFindings() {
		if finding.Attributes != nil && finding.Attributes.PolicyModifications != nil && len(*finding.Attributes.PolicyModifications) > 0 {
			return *finding.Attributes.PolicyModifications
		}
	}
	return nil
}

// findingExtraLocal mirrors the JSON shape of ufm.FindingExtra for deserialization
// when metadata arrives as map[string]interface{} (e.g. after JSON round-trip).
// Cannot import pkg/utils/ufm directly due to an import cycle.
type findingExtraLocal struct {
	Fingerprints           map[string]string          `json:"fingerprints,omitempty"`
	IsAutofixable          bool                       `json:"isAutofixable,omitempty"`
	Arguments              []string                   `json:"arguments,omitempty"`
	Suppression            *suppressionExtraLocal     `json:"suppression,omitempty"`
	MessageText            string                     `json:"messageText,omitempty"`
	MessageMarkdown        string                     `json:"messageMarkdown,omitempty"`
	RuleIndex              int                        `json:"ruleIndex"`
	PriorityScoreFactors   []priorityScoreFactorLocal `json:"priorityScoreFactors,omitempty"`
	PolicyOriginalLevel    string                     `json:"policyOriginalLevel,omitempty"`
	PolicySeverity         string                     `json:"policySeverity,omitempty"`
	PolicyOriginalSeverity string                     `json:"policyOriginalSeverity,omitempty"`
}

type suppressionExtraLocal struct {
	GUID       string `json:"guid,omitempty"`
	Category   string `json:"category,omitempty"`
	IgnoredBy  string `json:"ignoredBy,omitempty"`
	Email      string `json:"email,omitempty"`
	Expiration string `json:"expiration,omitempty"`
	IgnoredOn  string `json:"ignoredOn,omitempty"`
}

type priorityScoreFactorLocal struct {
	Label bool   `json:"label"`
	Type  string `json:"type"`
}

func getFindingExtraFromIssue(issue testapi.Issue, testResult testapi.TestResult) interface{} {
	extras, ok := testResult.GetMetadataValue("finding-extras").(map[string]interface{})
	if !ok {
		return nil
	}
	for _, finding := range issue.GetFindings() {
		if finding.Id == nil {
			continue
		}
		extra, found := extras[finding.Id.String()]
		if !found {
			continue
		}
		if m, isMap := extra.(map[string]interface{}); isMap {
			b, err := json.Marshal(m)
			if err != nil {
				return nil
			}
			var fe findingExtraLocal
			if err := json.Unmarshal(b, &fe); err != nil {
				return nil
			}
			return fe
		}
		return extra
	}
	return nil
}

type coverageLocal struct {
	Files       int    `json:"files"`
	IsSupported bool   `json:"isSupported"`
	Lang        string `json:"lang"`
	Type        string `json:"type"`
}

func getCoverageFromTestResult(testResult testapi.TestResult) interface{} {
	raw := testResult.GetMetadataValue("coverage")
	if raw == nil {
		return nil
	}

	if arr, ok := raw.([]interface{}); ok {
		b, err := json.Marshal(arr)
		if err != nil {
			return nil
		}
		var covs []coverageLocal
		if err := json.Unmarshal(b, &covs); err != nil {
			return nil
		}
		return covs
	}

	return raw
}

func getSnykCodeRuleFromIssue(issue testapi.Issue) *testapi.SnykCodeRuleProblem {
	for _, finding := range issue.GetFindings() {
		if finding.Attributes == nil {
			continue
		}
		for _, p := range finding.Attributes.Problems {
			disc, err := p.Discriminator()
			if err != nil || disc != "snyk_code_rule" {
				continue
			}
			rule, err := p.AsSnykCodeRuleProblem()
			if err == nil {
				return &rule
			}
		}
	}
	return nil
}

func fingerprintsJSON(extra interface{}, fallbackID string) string {
	var fps map[string]string
	if extra != nil {
		switch e := extra.(type) {
		case map[string]interface{}:
			if raw, ok := e["fingerprints"]; ok {
				if m, ok := raw.(map[string]interface{}); ok {
					fps = make(map[string]string, len(m))
					for k, v := range m {
						fps[k] = fmt.Sprintf("%v", v)
					}
				}
			}
		default:
			v := reflect.ValueOf(extra)
			if v.Kind() == reflect.Struct {
				f := v.FieldByName("Fingerprints")
				if f.IsValid() && !f.IsNil() {
					if m, ok := f.Interface().(map[string]string); ok {
						fps = m
					}
				}
			}
		}
	}

	if len(fps) == 0 {
		fps = map[string]string{
			"identity":              fallbackID,
			"snyk/asset/finding/v1": fallbackID,
		}
	}

	pairs := make([]string, 0, len(fps))
	for k, v := range fps {
		pairs = append(pairs, fmt.Sprintf("%s: %s", strconv.Quote(k), strconv.Quote(v)))
	}
	slices.Sort(pairs)
	return strings.Join(pairs, ",\n\t\t\t\t\t\t")
}

func derefStr(v interface{}) string {
	if v == nil {
		return ""
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return ""
		}
		return fmt.Sprintf("%v", rv.Elem().Interface())
	}
	return fmt.Sprintf("%v", v)
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
	fnMap["buildLocationsFromIssue"] = sarif.BuildLocations
	fnMap["buildFixFromIssue"] = sarif.BuildFixFromIssue
	fnMap["formatIssueMessage"] = sarif.FormatIssueMessage
	// UFM data access helpers
	fnMap["getExecutionFlowsFromIssue"] = getExecutionFlowsFromIssue
	fnMap["getPolicyModificationsFromIssue"] = getPolicyModificationsFromIssue
	fnMap["getFindingExtraFromIssue"] = getFindingExtraFromIssue
	fnMap["getCoverageFromTestResult"] = getCoverageFromTestResult
	fnMap["fingerprintsJSON"] = fingerprintsJSON
	fnMap["getSnykCodeRuleFromIssue"] = getSnykCodeRuleFromIssue
	fnMap["derefStr"] = derefStr
	return fnMap
}

func getCliTemplateFuncMap(tmpl *template.Template) template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["box"] = func(s string) string { return boxStyle.Render(s) }
	fnMap["toUpperCase"] = strings.ToUpper
	fnMap["toLowerCase"] = strings.ToLower
	fnMap["list"] = func(args ...testapi.FindingType) []testapi.FindingType { return args }
	fnMap["renderInSeverityColor"] = renderSeverityColor
	fnMap["colorBySeverity"] = renderInSeverityColor // 2-arg version from styles.go
	fnMap["renderGreen"] = renderGreen
	fnMap["renderGray"] = renderGray
	fnMap["renderCyan"] = renderCyan
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
	fnMap["getExecutionFlowsFromIssue"] = getExecutionFlowsFromIssue
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

type sourceLineCache struct {
	lines    map[string][]string
	baseDirs []string
}

const maxSourceFileSize = 10 * 1024 * 1024 // 10 MB

func newSourceLineCache(baseDirs []string) *sourceLineCache {
	return &sourceLineCache{
		lines:    make(map[string][]string),
		baseDirs: baseDirs,
	}
}

func (c *sourceLineCache) resolveFile(filePath string) string {
	if filepath.IsAbs(filePath) {
		if _, err := os.Stat(filePath); err == nil {
			return filePath
		}
		return ""
	}
	for _, base := range c.baseDirs {
		resolved := filepath.Join(base, filePath)
		if _, err := os.Stat(resolved); err == nil {
			return resolved
		}
	}
	return ""
}

func (c *sourceLineCache) loadFile(filePath string) []string {
	if cached, ok := c.lines[filePath]; ok {
		return cached
	}

	resolved := c.resolveFile(filePath)
	if resolved == "" {
		c.lines[filePath] = nil
		return nil
	}

	info, err := os.Stat(resolved)
	if err != nil || info.Size() > maxSourceFileSize {
		c.lines[filePath] = nil
		return nil
	}

	f, err := os.Open(resolved)
	if err != nil {
		c.lines[filePath] = nil
		return nil
	}
	defer f.Close()

	var fileLines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fileLines = append(fileLines, scanner.Text())
	}

	c.lines[filePath] = fileLines
	return fileLines
}

func (c *sourceLineCache) ReadLine(filePath string, line int) string {
	fileLines := c.loadFile(filePath)
	if line < 1 || line > len(fileLines) {
		return ""
	}
	return strings.TrimRight(fileLines[line-1], " \t")
}

func (c *sourceLineCache) ReadLineMarked(filePath string, line int, fromCol, toCol *int) [3]string {
	fullLine := c.ReadLine(filePath, line)
	if fullLine == "" || fromCol == nil {
		return [3]string{fullLine, "", ""}
	}
	fc := *fromCol - 1 // convert to 0-based
	if fc < 0 {
		fc = 0
	}
	if fc > len(fullLine) {
		fc = len(fullLine)
	}

	tc := len(fullLine)
	if toCol != nil {
		tc = *toCol // toCol is exclusive end
		if tc > len(fullLine) {
			tc = len(fullLine)
		}
	}
	if tc <= fc {
		tc = fc
	}

	return [3]string{fullLine[:fc], fullLine[fc:tc], fullLine[tc:]}
}

func resolveMessageArgs(text string, args []string) string {
	for i, arg := range args {
		text = strings.ReplaceAll(text, fmt.Sprintf("{%d}", i), arg)
	}
	return text
}

func getHTMLTemplateFuncMap(config configuration.Configuration) htmlTemplate.FuncMap {
	baseDirs := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	cache := newSourceLineCache(baseDirs)

	fnMap := htmlTemplate.FuncMap{}
	fnMap["severityColor"] = SeverityColor
	fnMap["severityLetter"] = SeverityLetter
	fnMap["toUpperCase"] = strings.ToUpper
	fnMap["toLowerCase"] = strings.ToLower
	fnMap["truncateText"] = TruncateText
	fnMap["markdownToHTML"] = MarkdownToHTML
	fnMap["sub"] = sub
	fnMap["list"] = func(args ...testapi.FindingType) []testapi.FindingType { return args }
	fnMap["getExecutionFlowsFromIssue"] = getExecutionFlowsFromIssue
	fnMap["getSnykCodeRuleFromIssue"] = getSnykCodeRuleFromIssue
	fnMap["getCoverageFromTestResult"] = getCoverageFromTestResult
	fnMap["getFindingExtraFromIssue"] = getFindingExtraFromIssue
	fnMap["readSourceLine"] = cache.ReadLine
	fnMap["readSourceLineMarked"] = cache.ReadLineMarked
	fnMap["resolveMessageArgs"] = resolveMessageArgs
	fnMap["dict"] = func(pairs ...interface{}) map[string]interface{} {
		m := make(map[string]interface{}, len(pairs)/2)
		for i := 0; i+1 < len(pairs); i += 2 {
			key, ok := pairs[i].(string)
			if ok {
				m[key] = pairs[i+1]
			}
		}
		return m
	}
	fnMap["index3"] = func(arr [3]string, i int) string { return arr[i] }
	fnMap["int"] = func(v interface{}) int {
		if p, ok := v.(*int); ok && p != nil {
			return *p
		}
		return toInt(v)
	}
	fnMap["reportTimestamp"] = func(testResults []testapi.TestResult) string {
		for _, tr := range testResults {
			if t := tr.GetCreatedAt(); t != nil {
				return t.Format("January 02, 2006 15:04 UTC")
			}
		}
		return time.Now().UTC().Format("January 02, 2006 15:04 UTC")
	}
	fnMap["getSortedIssuesDesc"] = func(summary *testapi.IssueSummary) []testapi.Issue {
		if summary == nil {
			return []testapi.Issue{}
		}
		sorting := FilterSeverityASC(json_schemas.DEFAULT_SEVERITIES, config.GetString(configuration.FLAG_SEVERITY_THRESHOLD))
		slices.Reverse(sorting)
		return summary.GetSortedIssues(sorting)
	}
	return fnMap
}

func SeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "#AB1A1A"
	case "high":
		return "#CE5019"
	case "medium":
		return "#D68000"
	case "low":
		return "#88879E"
	default:
		return "#88879E"
	}
}

func SeverityLetter(severity string) string {
	s := strings.ToUpper(strings.TrimSpace(severity))
	if len(s) == 0 {
		return "?"
	}
	return s[:1]
}

func TruncateText(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

var (
	mdLinkRegexp          = regexp.MustCompile(`\[([^\]]+)\]\(((?:[^()\s]|\([^()]*\))*)\)`)
	mdBoldRegexp          = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdInlineCodeRegexp    = regexp.MustCompile("`([^`]+)`")
	mdOrderedListRegexp   = regexp.MustCompile(`^\d+\.\s+(.*)`)
	mdTableSeparatorRegex = regexp.MustCompile(`^\|[\s:]*-+[\s:]*(\|[\s:]*-+[\s:]*)*\|?$`)
)

func MarkdownToHTML(input string) htmlTemplate.HTML {
	escaped := htmlTemplate.HTMLEscapeString(input)
	lines := strings.Split(escaped, "\n")

	var result strings.Builder
	inCodeBlock := false
	listTag := ""
	closeList := func() {
		if listTag != "" {
			result.WriteString("</" + listTag + ">")
			listTag = ""
		}
	}
	openList := func(tag string) {
		if listTag != tag {
			closeList()
			result.WriteString("<" + tag + ">")
			listTag = tag
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			closeList()
			if inCodeBlock {
				result.WriteString("</code></pre>")
			} else {
				result.WriteString("<pre><code>")
			}
			inCodeBlock = !inCodeBlock
			continue
		}

		if inCodeBlock {
			result.WriteString(line)
			result.WriteString("\n")
			continue
		}

		if trimmed == "" {
			closeList()
			continue
		}

		if isHorizontalRule(trimmed) {
			closeList()
			result.WriteString("<hr>")
			continue
		}

		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			openList("ul")
			result.WriteString("<li>")
			result.WriteString(applyInlineMarkdown(trimmed[2:]))
			result.WriteString("</li>")
			continue
		}

		if m := mdOrderedListRegexp.FindStringSubmatch(trimmed); m != nil {
			openList("ol")
			result.WriteString("<li>")
			result.WriteString(applyInlineMarkdown(m[1]))
			result.WriteString("</li>")
			continue
		}

		if isTableRow(trimmed) {
			closeList()
			i = renderTable(&result, lines, i)
			continue
		}

		closeList()
		renderBlockLine(&result, trimmed)
	}

	closeList()
	if inCodeBlock {
		result.WriteString("</code></pre>")
	}

	return htmlTemplate.HTML(result.String()) //nolint:gosec // input is HTML-escaped above before markdown conversion
}

func isHorizontalRule(s string) bool {
	return s == "---" || s == "***" || s == "___"
}

func isTableRow(s string) bool {
	return strings.HasPrefix(s, "|")
}

func parseTableCells(row string) []string {
	row = strings.TrimSpace(row)
	row = strings.TrimPrefix(row, "|")
	row = strings.TrimSuffix(row, "|")
	parts := strings.Split(row, "|")
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	return cells
}

func renderTable(result *strings.Builder, lines []string, startIndex int) int {
	i := startIndex
	headerCells := parseTableCells(lines[i])
	i++

	hasSeparator := i < len(lines) && mdTableSeparatorRegex.MatchString(strings.TrimSpace(lines[i]))
	if hasSeparator {
		i++
	}

	result.WriteString("<table><thead><tr>")
	for _, cell := range headerCells {
		result.WriteString("<th>")
		result.WriteString(applyInlineMarkdown(cell))
		result.WriteString("</th>")
	}
	result.WriteString("</tr></thead><tbody>")

	for i < len(lines) && isTableRow(strings.TrimSpace(lines[i])) {
		trimmed := strings.TrimSpace(lines[i])
		if mdTableSeparatorRegex.MatchString(trimmed) {
			i++
			continue
		}
		cells := parseTableCells(trimmed)
		result.WriteString("<tr>")
		for _, cell := range cells {
			result.WriteString("<td>")
			result.WriteString(applyInlineMarkdown(cell))
			result.WriteString("</td>")
		}
		result.WriteString("</tr>")
		i++
	}

	result.WriteString("</tbody></table>")
	return i - 1
}

func renderBlockLine(result *strings.Builder, trimmed string) {
	if heading, level := parseHeading(trimmed); heading != "" {
		tag := fmt.Sprintf("h%d", level)
		result.WriteString("<" + tag + ">")
		result.WriteString(applyInlineMarkdown(heading))
		result.WriteString("</" + tag + ">")
		return
	}
	result.WriteString("<p>")
	result.WriteString(applyInlineMarkdown(trimmed))
	result.WriteString("</p>")
}

func parseHeading(line string) (string, int) {
	level := 0
	for _, c := range line {
		if c == '#' {
			level++
		} else {
			break
		}
	}
	if level > 0 && level <= 6 && len(line) > level && line[level] == ' ' {
		return strings.TrimSpace(line[level+1:]), level
	}
	return "", 0
}

func isAllowedHref(href string) bool {
	normalized := strings.ToLower(strings.TrimSpace(href))
	if strings.HasPrefix(normalized, "javascript:") || strings.HasPrefix(normalized, "data:") || strings.HasPrefix(normalized, "vbscript:") {
		return false
	}
	if strings.HasPrefix(normalized, "//") {
		return false
	}
	return true
}

func applyInlineMarkdown(s string) string {
	s = mdLinkRegexp.ReplaceAllStringFunc(s, func(match string) string {
		parts := mdLinkRegexp.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		text, href := parts[1], parts[2]
		if !isAllowedHref(href) {
			return text + " (" + href + ")"
		}
		return "\x00LINK_START\x00" + href + "\x00LINK_MID\x00" + text + "\x00LINK_END\x00"
	})
	s = mdBoldRegexp.ReplaceAllString(s, `<strong>$1</strong>`)
	s = mdInlineCodeRegexp.ReplaceAllString(s, `<code>$1</code>`)
	s = strings.ReplaceAll(s, "\x00LINK_START\x00", `<a href="`)
	s = strings.ReplaceAll(s, "\x00LINK_MID\x00", `" target="_blank" rel="noopener noreferrer">`)
	s = strings.ReplaceAll(s, "\x00LINK_END\x00", `</a>`)
	return s
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
	defaultMap["getFindingTypesFromMultipleTestResults"] = getFindingTypesFromMultipleTestResults
	defaultMap["getIssuesFromTestResult"] = func(testResults testapi.TestResult, findingType ...testapi.FindingType) []testapi.Issue {
		return utils.ValueOf(testapi.GetIssuesFromTestResult(testResults, findingType))
	}
	defaultMap["getIssuesFromMultipleTestResults"] = func(testResults []testapi.TestResult, findingType ...testapi.FindingType) []testapi.Issue {
		var allIssues []testapi.Issue
		for _, result := range testResults {
			allIssues = append(allIssues, utils.ValueOf(testapi.GetIssuesFromTestResult(result, findingType))...)
		}
		return allIssues
	}
	defaultMap["getIssueMetadata"] = func(issue testapi.Issue, key string) interface{} {
		value, found := issue.GetData(key)
		if !found {
			return nil
		}
		return value
	}
	defaultMap["convertTypeToIssueName"] = convertTypeToIssueName
	defaultMap["sortAndFilterIssues"] = sortAndFilterIssues(config)
	defaultMap["determineProductNameFromFindingTypes"] = determineProductNameFromFindingTypes
	defaultMap["getRemediationSummary"] = ufm_helpers.GetRemediationSummary
	defaultMap["getSeverities"] = func() []string {
		return json_schemas.DEFAULT_SEVERITIES
	}
	defaultMap["getSummariesFromIssues"] = testapi.GetSummariesFromIssues
	defaultMap["newFindingTypeSummary"] = func(ft testapi.FindingType, issues []testapi.Issue) interface{} {
		return struct {
			FindingType testapi.FindingType
			Issues      []testapi.Issue
		}{FindingType: ft, Issues: issues}
	}
	defaultMap["getSortedIssuesFromSummary"] = func(summary *testapi.IssueSummary) []testapi.Issue {
		if summary == nil {
			return []testapi.Issue{}
		}
		sorting := FilterSeverityASC(json_schemas.DEFAULT_SEVERITIES, config.GetString(configuration.FLAG_SEVERITY_THRESHOLD))
		return summary.GetSortedIssues(sorting)
	}
	defaultMap["getTargetId"] = func(path string) (string, error) {
		return target.GetTargetId(path, target.AutoDetectedTargetId, target.WithConfiguredRepository(config))
	}
	defaultMap["deduplicateIssues"] = deduplicateIssues

	return defaultMap
}

type issueDedupeKey string

const (
	DedupeByProblemID issueDedupeKey = "problemID"
	DedupeByID        issueDedupeKey = "id"
)

// deduplicateIssues returns a subset of issues with unique keys, preserving order (first-wins).
func deduplicateIssues(issues []testapi.Issue, key issueDedupeKey) []testapi.Issue {
	seen := make(map[string]bool)
	result := make([]testapi.Issue, 0, len(issues))
	for _, issue := range issues {
		var field string
		switch key {
		case DedupeByProblemID:
			field = issue.GetProblemID()
		case DedupeByID:
			field = issue.GetID()
		default:
			fmt.Fprintf(os.Stderr, "warning: unsupported issueDedupeKey %q, skipping deduplication for issue\n", key)
		}
		if field != "" && !seen[field] {
			seen[field] = true
			result = append(result, issue)
		}
	}
	return result
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
	case testapi.FindingTypeSecrets:
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
	case uint16:
		return int(val)
	case uint32:
		return int(val)
	case float64:
		return int(val)
	case float32:
		return int(val)
	case string:
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

	if slices.Contains(findingTypes, testapi.FindingTypeSecrets) {
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

	// Add finding types from ScanConfiguration
	for _, t := range getDefaultFindingTypesFromConfig(testResults) {
		findingTypes[t] = true
	}

	// Add finding types derived from actual findings
	// todo: this is potentially an expensive intermediate conversion to issues, which we could cache or optimize differently.
	issues, err := testapi.NewIssuesFromTestResult(context.Background(), testResults)
	if err == nil {
		for _, i := range issues {
			findingTypes[i.GetFindingType()] = true
		}
	}

	findingTypesList := slices.Collect(maps.Keys(findingTypes))
	if len(findingTypesList) == 0 {
		return []testapi.FindingType{"no findings type found"}
	}

	slices.Sort(findingTypesList)
	slices.Reverse(findingTypesList)

	return findingTypesList
}

func getFindingTypesFromMultipleTestResults(testResults []testapi.TestResult) []testapi.FindingType {
	findingTypes := map[testapi.FindingType]bool{}
	for _, result := range testResults {
		for _, ft := range getFindingTypesFromTestResult(result) {
			findingTypes[ft] = true
		}
	}
	findingTypesList := slices.Collect(maps.Keys(findingTypes))
	if len(findingTypesList) == 0 {
		return []testapi.FindingType{"no findings type found"}
	}
	slices.Sort(findingTypesList)
	slices.Reverse(findingTypesList)
	return findingTypesList
}

func getDefaultFindingTypesFromConfig(testResults testapi.TestResult) []testapi.FindingType {
	if testResults == nil {
		return nil
	}
	config := testResults.GetTestConfiguration()
	if config == nil || config.ScanConfig == nil {
		return nil
	}
	return config.ScanConfig.GetDefaultFindingTypes()
}
