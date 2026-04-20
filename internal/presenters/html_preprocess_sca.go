package presenters

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return 0
		}
		return int(i)
	default:
		return 0
	}
}

func stringFromAny(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

var scaSeverityOrder = map[string]int{
	"low":      0,
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// PreprocessLegacySCAJSON builds template data like snyk-to-html processData/generateTemplate (without remediation).
func PreprocessLegacySCAJSON(raw []byte, showSummaryOnly bool) (map[string]any, error) {
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse SCA JSON: %w", err)
	}

	var merged map[string]any
	switch v := data.(type) {
	case []any:
		merged = mergeSCAProjects(v)
	case map[string]any:
		merged = v
	default:
		return nil, fmt.Errorf("unsupported SCA JSON shape")
	}

	vulnsRaw, hasVu := merged["vulnerabilities"]
	if !hasVu || vulnsRaw == nil {
		merged["vulnerabilities"] = []any{}
		vulnsRaw = merged["vulnerabilities"]
	}

	gmeta := groupVulns(vulnsRaw)
	sorted := sortVulnGroups(gmeta)

	uniq := 0
	if u, uok := gmeta["uniqueCount"].(int); uok {
		uniq = u
	}
	pathsCnt := 0
	if p, pok := gmeta["pathsCount"].(int); pok {
		pathsCnt = p
	}

	paths, ok := merged["paths"].([]any)
	if ok && len(paths) == 1 {
		if p0, ok := paths[0].(map[string]any); ok {
			if pm, ok := p0["packageManager"].(string); ok {
				merged["packageManager"] = pm
			}
		}
	}

	merged["vulnerabilities"] = sorted
	merged["hasMetatableData"] = nonEmptyString(merged, "projectName") ||
		nonEmptyString(merged, "path") ||
		nonEmptyString(merged, "displayTargetFile")
	merged["uniqueCount"] = uniq
	merged["summary"] = fmt.Sprintf("%d vulnerable dependency paths", pathsCnt)
	merged["showSummaryOnly"] = showSummaryOnly
	merged["d"] = time.Now().UTC().Format(time.RFC3339)
	return merged, nil
}

func nonEmptyString(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	s, ok := v.(string)
	return ok && s != ""
}

func mergeSCAProjects(dataArray []any) map[string]any {
	var vulnsArrays [][]any
	var paths []any
	totalDep := 0
	totalCount := 0

	for _, proj := range dataArray {
		p, ok := proj.(map[string]any)
		if !ok {
			continue
		}
		var vl []any
		if v, ok := p["vulnerabilities"].([]any); ok {
			vl = v
		}
		out := make([]any, 0, len(vl))
		for _, vuln := range vl {
			vm, ok := vuln.(map[string]any)
			if !ok {
				continue
			}
			c := make(map[string]any)
			for k, val := range vm {
				c[k] = val
			}
			if dtf, ok := p["displayTargetFile"]; ok {
				c["displayTargetFile"] = dtf
			}
			if pt, ok := p["path"]; ok {
				c["path"] = pt
			}
			out = append(out, c)
		}
		vulnsArrays = append(vulnsArrays, out)

		if dc, ok := p["dependencyCount"].(float64); ok {
			totalDep += int(dc)
		}
		if v, ok := p["vulnerabilities"].([]any); ok {
			totalCount += len(v)
		}
		paths = append(paths, map[string]any{
			"path":              p["path"],
			"packageManager":    p["packageManager"],
			"displayTargetFile": p["displayTargetFile"],
		})
	}

	aggregate := []any{}
	for _, a := range vulnsArrays {
		aggregate = append(aggregate, a...)
	}

	return map[string]any{
		"vulnerabilities": aggregate,
		"uniqueCount":     totalCount,
		"summary":         fmt.Sprintf("%d vulnerable dependency paths", len(aggregate)),
		"dependencyCount": totalDep,
		"paths":           paths,
	}
}

func groupVulns(vulnsRaw any) map[string]any {
	result := make(map[string]any)
	uniqueCount := 0
	pathsCount := 0

	vulns, ok := vulnsRaw.([]any)
	if !ok || vulns == nil {
		return map[string]any{
			"vulnerabilities": result,
			"uniqueCount":     0,
			"pathsCount":      0,
		}
	}

	for _, v := range vulns {
		vuln, ok := v.(map[string]any)
		if !ok {
			continue
		}
		id, ok := vuln["id"].(string)
		if !ok || id == "" {
			continue
		}
		if _, exists := result[id]; !exists {
			result[id] = map[string]any{
				"list":     []any{vuln},
				"metadata": metadataForVuln(vuln),
			}
			pathsCount++
			uniqueCount++
		} else {
			g, ok := result[id].(map[string]any)
			if !ok {
				continue
			}
			lst, ok := g["list"].([]any)
			if !ok {
				continue
			}
			lst = append(lst, vuln)
			g["list"] = lst
			pathsCount++
		}
	}

	return map[string]any{
		"vulnerabilities": result,
		"uniqueCount":     uniqueCount,
		"pathsCount":      pathsCount,
	}
}

func metadataForVuln(vuln map[string]any) map[string]any {
	cveSpaced, cveLineBreaks := concatenateCVEs(vuln)
	sev := ""
	if s, ok := vuln["severity"].(string); ok {
		sev = s
	}
	sv := scaSeverityOrder[strings.ToLower(sev)]
	meta := map[string]any{
		"id":              vuln["id"],
		"title":           vuln["title"],
		"name":            vuln["name"],
		"info":            stringField(vuln, "info", "No information available."),
		"severity":        sev,
		"severityValue":   sv,
		"description":     stringField(vuln, "description", "No description available."),
		"fixedIn":         vuln["fixedIn"],
		"packageManager":  vuln["packageManager"],
		"version":         vuln["version"],
		"cvssScore":       vuln["cvssScore"],
		"cveSpaced":       nonEmptyOr(cveSpaced, "No CVE found."),
		"cveLineBreaks":   nonEmptyOr(cveLineBreaks, "No CVE found."),
		"disclosureTime":  dateFromDateTimeString(getStr(vuln, "disclosureTime")),
		"publicationTime": dateFromDateTimeString(getStr(vuln, "publicationTime")),
	}
	if rs, ok := vuln["riskScore"].(float64); ok {
		meta["riskScore"] = rs
	} else if rs, ok := vuln["riskScore"].(int); ok {
		meta["riskScore"] = rs
	}
	if lic := vuln["license"]; lic != nil {
		meta["license"] = lic
	}
	if r, ok := vuln["reachability"].(string); ok {
		meta["reachability"] = processReachability(r)
	}
	return meta
}

func stringField(v map[string]any, key, def string) string {
	if x, ok := v[key].(string); ok && x != "" {
		return x
	}
	return def
}

func getStr(v map[string]any, key string) string {
	if x, ok := v[key].(string); ok {
		return x
	}
	return ""
}

func nonEmptyOr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func processReachability(r string) any {
	switch r {
	case "reachable":
		return "Reachable"
	case "no-path-found":
		return "No Reachable Path Found"
	default:
		return nil
	}
}

func concatenateCVEs(vuln map[string]any) (spaced, lineBreaks string) {
	ids, ok := vuln["identifiers"].(map[string]any)
	if !ok {
		return "", ""
	}
	cveArr, ok := ids["CVE"].([]any)
	if !ok {
		return "", ""
	}
	for _, c := range cveArr {
		cs, ok := c.(string)
		if !ok {
			continue
		}
		link := fmt.Sprintf(`<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s">%s</a>`, cs, cs)
		spaced += link + "&nbsp;"
		lineBreaks += link + "</br>"
	}
	return spaced, lineBreaks
}

func dateFromDateTimeString(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func sortVulnGroups(gmeta map[string]any) []any {
	raw, ok := gmeta["vulnerabilities"].(map[string]any)
	if !ok {
		return []any{}
	}
	type grp struct {
		id  string
		val map[string]any
	}
	var groups []grp
	for id, v := range raw {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		groups = append(groups, grp{id: id, val: vm})
	}
	sort.Slice(groups, func(i, j int) bool {
		mi, ok1 := groups[i].val["metadata"].(map[string]any)
		mj, ok2 := groups[j].val["metadata"].(map[string]any)
		if !ok1 || !ok2 {
			return false
		}
		svi := intFromAny(mi["severityValue"])
		svj := intFromAny(mj["severityValue"])
		if svi != svj {
			return svi > svj
		}
		ni := stringFromAny(mi["name"])
		nj := stringFromAny(mj["name"])
		return ni > nj
	})
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.val)
	}
	return out
}
