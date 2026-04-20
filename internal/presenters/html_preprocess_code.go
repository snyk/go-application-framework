package presenters

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/snyk/code-client-go/sarif"
)

func codeSeverityFromLevel(level string) string {
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "info", "note":
		return "low"
	default:
		return "low"
	}
}

// PreprocessCodeSARIF enriches Snyk Code SARIF the same way snyk-to-html processCodeData does.
func PreprocessCodeSARIF(sarifJSON []byte, showSummaryOnly bool) (map[string]any, error) {
	var doc sarif.SarifDocument
	if err := json.Unmarshal(sarifJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	if len(doc.Runs) == 0 {
		return emptyCodeReport(cwd, showSummaryOnly), nil
	}
	run := doc.Runs[0]
	rules := run.Tool.Driver.Rules

	counter := []struct {
		severity string
		counter  int
		ignored  int
	}{
		{"high", 0, 0},
		{"medium", 0, 0},
		{"low", 0, 0},
	}
	severityIdx := map[string]int{"high": 0, "medium": 1, "low": 2}

	results := make([]sarif.Result, len(run.Results))
	copy(results, run.Results)

	for i := range results {
		issue := &results[i]
		sevText := codeSeverityFromLevel(issue.Level)
		idx := severityIdx[sevText]
		if isIssueIgnoredSARIF(issue.Suppressions) {
			counter[idx].ignored++
		} else {
			counter[idx].counter++
		}
	}

	slices.SortFunc(results, func(a, b sarif.Result) int {
		return b.Properties.PriorityScore - a.Properties.PriorityScore
	})

	vulns := make([]any, 0, len(results))
	for i := range results {
		m := resultToMap(&results[i], rules)
		enrichCodeResultMap(m, cwd)
		vulns = append(vulns, m)
	}
	vulns = sortVulnsBySuppression(vulns)

	totalIssues := len(run.Results)
	ignoredCount := countIgnoredFromSevCounter(counter)
	details := runPropertiesToMap(run.Properties)

	project := map[string]any{
		"details":            details,
		"sourceFilePath":     cwd,
		"vulnsummarycounter": sevCounterToMaps(counter),
		"vulnerabilities":    vulns,
	}
	return map[string]any{
		"projects":          []any{project},
		"showSummaryOnly":   showSummaryOnly,
		"totalIssues":       totalIssues,
		"reportDescription": generateCodeReportDescription(totalIssues, ignoredCount),
		"d":                 time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func emptyCodeReport(cwd string, showSummaryOnly bool) map[string]any {
	z := []struct {
		severity string
		counter  int
		ignored  int
	}{
		{"high", 0, 0},
		{"medium", 0, 0},
		{"low", 0, 0},
	}
	project := map[string]any{
		"details":            map[string]any{},
		"sourceFilePath":     cwd,
		"vulnsummarycounter": sevCounterToMaps(z),
		"vulnerabilities":    []any{},
	}
	return map[string]any{
		"projects":          []any{project},
		"showSummaryOnly":   showSummaryOnly,
		"totalIssues":       0,
		"reportDescription": generateCodeReportDescription(0, 0),
		"d":                 time.Now().UTC().Format(time.RFC3339),
	}
}

func countIgnoredFromSevCounter(counter []struct {
	severity string
	counter  int
	ignored  int
}) int {
	n := 0
	for i := range counter {
		n += counter[i].ignored
	}
	return n
}

func sevCounterToMaps(counter []struct {
	severity string
	counter  int
	ignored  int
}) []map[string]any {
	out := make([]map[string]any, len(counter))
	for i := range counter {
		out[i] = map[string]any{
			"severity": counter[i].severity,
			"counter":  counter[i].counter,
			"ignored":  counter[i].ignored,
		}
	}
	return out
}

func generateCodeReportDescription(issueCount, ignoredCount int) string {
	if issueCount == 0 {
		return "No issues found"
	}
	if ignoredCount > 0 {
		openCount := issueCount - ignoredCount
		return fmt.Sprintf("Found %d open issues (%d ignored)", openCount, ignoredCount)
	}
	return fmt.Sprintf("Found %d issues", issueCount)
}

func findRule(rules []sarif.Rule, id string) *sarif.Rule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

func isIssueIgnoredSARIF(suppressions []sarif.Suppression) bool {
	if len(suppressions) == 0 {
		return false
	}
	s := getHighestSuppression(suppressions)
	if s == nil {
		return false
	}
	return s.Status == sarif.Accepted || s.Status == ""
}

func getHighestSuppression(suppressions []sarif.Suppression) *sarif.Suppression {
	for i := range suppressions {
		if suppressions[i].Status == sarif.Accepted || suppressions[i].Status == "" {
			return &suppressions[i]
		}
	}
	for i := range suppressions {
		if suppressions[i].Status == sarif.UnderReview {
			return &suppressions[i]
		}
	}
	for i := range suppressions {
		if suppressions[i].Status == sarif.Rejected {
			return &suppressions[i]
		}
	}
	return nil
}

func resultToMap(issue *sarif.Result, rules []sarif.Rule) map[string]any {
	b, err := json.Marshal(issue)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	m["severitytext"] = codeSeverityFromLevel(issue.Level)
	if rule := findRule(rules, issue.RuleID); rule != nil {
		rb, err := json.Marshal(rule)
		if err == nil {
			var rm map[string]any
			if json.Unmarshal(rb, &rm) == nil {
				m["ruleiddesc"] = rm
			}
		}
	}
	if len(issue.Suppressions) > 0 {
		if sup := processSuppression(issue.Suppressions[0]); sup != nil {
			m["suppression"] = sup
		}
	}
	return m
}

func enrichCodeResultMap(m map[string]any, cwd string) {
	enrichPrimaryLocationSnippet(m, cwd)
	enrichCodeFlowSnippets(m, cwd)
}

func enrichPrimaryLocationSnippet(m map[string]any, cwd string) {
	if locs, ok := m["locations"].([]any); ok && len(locs) > 0 {
		if loc, ok := locs[0].(map[string]any); ok {
			if pl, ok := loc["physicalLocation"].(map[string]any); ok {
				cs := readCodeSnippetFromPhysicalMap(pl, cwd)
				attachCodeStringMap(pl, cs)
			}
		}
	}
}

func enrichCodeFlowSnippets(m map[string]any, cwd string) {
	flows, ok := m["codeFlows"].([]any)
	if !ok || len(flows) == 0 {
		return
	}
	flow, ok := flows[0].(map[string]any)
	if !ok {
		return
	}
	tfs, ok := flow["threadFlows"].([]any)
	if !ok || len(tfs) == 0 {
		return
	}
	tf, ok := tfs[0].(map[string]any)
	if !ok {
		return
	}
	locs, ok := tf["locations"].([]any)
	if !ok {
		return
	}
	oldURI := ""
	for _, tl := range locs {
		tlm, ok := tl.(map[string]any)
		if !ok {
			continue
		}
		innerLoc, ok := tlm["location"].(map[string]any)
		if !ok {
			continue
		}
		pl, ok := innerLoc["physicalLocation"].(map[string]any)
		if !ok {
			continue
		}
		uri := ""
		if al, ok := pl["artifactLocation"].(map[string]any); ok {
			if u, ok := al["uri"].(string); ok {
				uri = u
			}
		}
		if uri == oldURI {
			pl["isshowfilename"] = false
		} else {
			pl["isshowfilename"] = true
		}
		oldURI = uri
		cs := readCodeSnippetFromPhysicalMap(pl, cwd)
		attachCodeStringMap(pl, cs)
	}
}

func processSuppression(s sarif.Suppression) map[string]any {
	cat := string(s.Properties.Category)
	if cat == "" {
		cat = "unknown"
	}
	ignoredBy := map[string]any{
		"name":  s.Properties.IgnoredBy.Name,
		"email": "?",
	}
	if s.Properties.IgnoredBy.Email != nil {
		ignoredBy["email"] = *s.Properties.IgnoredBy.Email
	}
	out := map[string]any{
		"justification": s.Justification,
		"category":      cat,
		"status":        string(s.Status),
		"ignoredOn":     s.Properties.IgnoredOn,
		"ignoredBy":     ignoredBy,
	}
	if s.Properties.Expiration != nil {
		out["expiration"] = *s.Properties.Expiration
	}
	return out
}

func sortVulnsBySuppression(vulns []any) []any {
	hasSup := false
	for _, v := range vulns {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := vm["suppression"]; ok {
			hasSup = true
			break
		}
	}
	if !hasSup {
		return vulns
	}
	slices.SortFunc(vulns, func(a, b any) int {
		am, ok1 := a.(map[string]any)
		bm, ok2 := b.(map[string]any)
		if !ok1 || !ok2 {
			return 0
		}
		_, aSup := am["suppression"]
		_, bSup := bm["suppression"]
		switch {
		case aSup && !bSup:
			return 1
		case !aSup && bSup:
			return -1
		default:
			return 0
		}
	})
	return vulns
}

func runPropertiesToMap(p sarif.RunProperties) map[string]any {
	b, err := json.Marshal(p)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}

type codeSnippet struct {
	Codelineno     int    `json:"codelineno"`
	Block          bool   `json:"block"`
	Codesource     string `json:"codesource"`
	Codepremarker  string `json:"codepremarker"`
	Codemarker     string `json:"codemarker"`
	Codepostmarker string `json:"codepostmarker"`
}

func decodeArtifactURI(uri string) string {
	u := strings.TrimSpace(uri)
	if u == "" {
		return ""
	}
	dec, err := url.PathUnescape(u)
	if err == nil && dec != "" {
		u = dec
	}
	if strings.HasPrefix(u, "file://") {
		p := strings.TrimPrefix(u, "file://")
		if idx := strings.Index(p, "/"); idx >= 0 && strings.HasPrefix(p, "localhost") {
			// file://localhost/path
			p = p[idx+1:]
		}
		return filepath.Clean(p)
	}
	return filepath.Clean(u)
}

func readCodeSnippetFromPhysicalMap(pl map[string]any, cwd string) []codeSnippet {
	al, ok := pl["artifactLocation"].(map[string]any)
	if !ok {
		return nil
	}
	uriVal, ok := al["uri"]
	if !ok {
		return nil
	}
	uri, ok := uriVal.(string)
	if !ok {
		return nil
	}
	path := decodeArtifactURI(uri)
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	reg, ok := pl["region"].(map[string]any)
	if !ok {
		return nil
	}
	startLine := int(numberToFloat64(reg["startLine"]))
	endLine := int(numberToFloat64(reg["endLine"]))
	startCol := int(numberToFloat64(reg["startColumn"]))
	endCol := int(numberToFloat64(reg["endColumn"]))
	if startLine < 1 || endLine < 1 {
		return nil
	}
	lineData, err := processCodeLines(path, startLine, endLine, startCol, endCol)
	if err != nil || len(lineData) == 0 {
		return nil
	}
	return lineData
}

func numberToFloat64(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0
		}
		return f
	default:
		return 0
	}
}

func attachCodeStringMap(pl map[string]any, cs []codeSnippet) {
	if len(cs) == 0 {
		return
	}
	arr := make([]any, 0, len(cs))
	for i := range cs {
		b, err := json.Marshal(cs[i])
		if err != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		arr = append(arr, m)
	}
	pl["codeString"] = arr
}

// processCodeLines mirrors snyk-to-html/src/lib/codeutil.ts processCodeLine (intentionally dense).
//
//nolint:gocyclo // logic ported from Node line-by-line
func processCodeLines(filePath string, startLine, endLine, startColumn, endColumn int) ([]codeSnippet, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNum := 1
	multi := startLine != endLine
	cs := codeSnippet{
		Block: multi,
	}
	if startColumn < 1 {
		startColumn = 1
	}
	for sc.Scan() {
		line := sc.Text()
		parseline := line
		if lineNum == startLine {
			var columnEndOfLine int
			if multi {
				columnEndOfLine = len(parseline)
			} else {
				columnEndOfLine = endColumn
				if columnEndOfLine > len(parseline) {
					columnEndOfLine = len(parseline)
				}
			}
			sc0 := startColumn - 1
			if sc0 > len(parseline) {
				sc0 = len(parseline)
			}
			if columnEndOfLine < sc0 {
				columnEndOfLine = sc0
			}
			cs.Codelineno = lineNum
			cs.Codepremarker = parseline[0:sc0]
			cs.Codemarker = parseline[sc0:columnEndOfLine]
		}
		if lineNum == endLine {
			if multi {
				ec := endColumn
				if ec > len(parseline) {
					ec = len(parseline)
				}
				cs.Codemarker = cs.Codemarker + "\n" + parseline[0:ec]
				cs.Codepostmarker = parseline[ec:]
			} else {
				ec := endColumn
				if ec > len(parseline) {
					ec = len(parseline)
				}
				cs.Codepostmarker = parseline[ec:]
			}
			return []codeSnippet{cs}, sc.Err()
		}
		if lineNum > startLine && lineNum < endLine {
			cs.Codemarker = cs.Codemarker + "\n" + parseline
		}
		lineNum++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cs.Codelineno == 0 {
		return nil, fmt.Errorf("no lines read")
	}
	return []codeSnippet{cs}, nil
}
