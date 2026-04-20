package presenters

import (
	"bytes"
	"encoding/json"
	"fmt"
	htmlstd "html"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mailgun/raymond/v2"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/renderer/html"
)

// defaultRemediationText matches snyk-to-html/src/lib/snyk-to-html.ts.
const defaultRemediationText = "## Remediation\nThere is no remediation at the moment"

var htmlMarkdownEngine = goldmark.New(
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

func markdownToHTML(src string) raymond.SafeString {
	var buf bytes.Buffer
	if err := htmlMarkdownEngine.Convert([]byte(src), &buf); err != nil {
		return raymond.SafeString(htmlstd.EscapeString(src))
	}
	return raymond.SafeString(buf.String())
}

func registerHTMLHelpers(tpl *raymond.Template) {
	tpl.RegisterHelper("markdown", helperMarkdown)
	tpl.RegisterHelper("moment", helperMoment)
	tpl.RegisterHelper("count", helperCount)
	tpl.RegisterHelper("dump", helperDump)
	tpl.RegisterHelper("isDoubleArray", helperIsDoubleArray)
	tpl.RegisterHelper("if_eq", helperIfEq)
	tpl.RegisterHelper("if_gt", helperIfGt)
	tpl.RegisterHelper("if_not_eq", helperIfNotEq)
	tpl.RegisterHelper("if_any", helperIfAny)
	tpl.RegisterHelper("ifCond", helperIfCond)
	tpl.RegisterHelper("getRemediation", helperGetRemediation)
	tpl.RegisterHelper("severityLabel", helperSeverityLabel)
	tpl.RegisterHelper("startsWith", helperStartsWith)
	tpl.RegisterHelper("formatDate", helperFormatDate)
	tpl.RegisterHelper("firstInitial", helperFirstInitial)
}

func helperMarkdown(src string) raymond.SafeString {
	if src == "" {
		return raymond.SafeString("")
	}
	return markdownToHTML(src)
}

// helperMoment mirrors snyk-to-html formatDateTime when date is nil (uses current UTC time).
func helperMoment(date interface{}, format string) string {
	t := time.Now().UTC()
	if date != nil {
		if s, ok := date.(string); ok && s != "" {
			if parsed, err := time.Parse(time.RFC3339, s); err == nil {
				t = parsed.UTC()
			} else if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
				t = parsed.UTC()
			}
		}
	}
	return formatMomentTime(t, format)
}

func formatMomentTime(t time.Time, format string) string {
	day := t.UTC().Day()
	ordinal := ordinalSuffix(day)
	dayWithSuffix := fmt.Sprintf("%d%s", day, ordinal)
	hours := t.UTC().Hour()
	minutes := t.UTC().Minute()
	seconds := t.UTC().Second()
	ampm := "am"
	if hours >= 12 {
		ampm = "pm"
	}
	formattedHours := hours % 12
	if formattedHours == 0 {
		formattedHours = 12
	}
	monthNames := []string{
		"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December",
	}
	repl := map[string]string{
		"MMMM": monthNames[t.UTC().Month()-1],
		"Do":   dayWithSuffix,
		"YYYY": fmt.Sprintf("%d", t.UTC().Year()),
		"h":    fmt.Sprintf("%d", formattedHours),
		"mm":   fmt.Sprintf("%02d", minutes),
		"ss":   fmt.Sprintf("%02d", seconds),
		"a":    ampm,
		"z":    "UTC",
		"Z":    "+00:00",
	}
	// Apply longest tokens first to avoid partial matches.
	out := format
	for _, token := range []string{"MMMM", "Do", "YYYY", "mm", "ss", "Z", "z", "a", "h"} {
		if v, ok := repl[token]; ok {
			out = strings.ReplaceAll(out, token, v)
		}
	}
	return out
}

func ordinalSuffix(day int) string {
	if day > 3 && day < 21 {
		return "th"
	}
	switch day % 10 {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	default:
		return "th"
	}
}

func helperCount(data interface{}) interface{} {
	if data == nil {
		return nil
	}
	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return v.Len()
	case reflect.Map:
		return v.Len()
	case reflect.String:
		return len(v.String())
	default:
		return nil
	}
}

func helperDump(data interface{}, spacer interface{}) string {
	indent := ""
	switch s := spacer.(type) {
	case float64:
		indent = strings.Repeat(" ", int(s))
	case int:
		indent = strings.Repeat(" ", s)
	case int64:
		indent = strings.Repeat(" ", int(s))
	case string:
		indent = s
	}
	b, err := json.MarshalIndent(data, "", indent)
	if err != nil {
		return ""
	}
	return string(b)
}

func helperIsDoubleArray(data interface{}, options *raymond.Options) string {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		return options.Inverse()
	}
	if v.Len() == 0 {
		return options.Inverse()
	}
	elem := v.Index(0)
	if elem.Kind() == reflect.Interface {
		elem = elem.Elem()
	}
	if elem.Kind() == reflect.Slice || elem.Kind() == reflect.Array {
		return options.Fn()
	}
	return options.Inverse()
}

func helperIfEq(a, b interface{}, options *raymond.Options) string {
	if looseEqual(a, b) {
		return options.Fn()
	}
	return options.Inverse()
}

func looseEqual(a, b interface{}) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	fa, okA := toFloatOk(a)
	fb, okB := toFloatOk(b)
	if okA && okB {
		return fa == fb
	}
	return false
}

func helperIfGt(a, b interface{}, options *raymond.Options) string {
	if cmpFloats(a, b) > 0 {
		return options.Fn()
	}
	return options.Inverse()
}

func helperIfNotEq(a, b interface{}, options *raymond.Options) string {
	if !looseEqual(a, b) {
		return options.Fn()
	}
	return options.Inverse()
}

func helperIfAny(a, b interface{}, options *raymond.Options) string {
	if truthy(a) || truthy(b) {
		return options.Fn()
	}
	return options.Inverse()
}

func truthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Ptr, reflect.Interface:
			return !rv.IsNil() && truthy(rv.Elem().Interface())
		default:
			return true
		}
	}
}

func helperIfCond(v1, operator, v2 interface{}, options *raymond.Options) string {
	op, ok := operator.(string)
	if !ok {
		return options.Inverse()
	}
	var pred bool
	switch op {
	case "==":
		pred = looseEqual(v1, v2)
	case "===":
		pred = v1 == v2
	case "<":
		pred = cmpFloats(v1, v2) < 0
	case "<=":
		pred = cmpFloats(v1, v2) <= 0
	case ">":
		pred = cmpFloats(v1, v2) > 0
	case ">=":
		pred = cmpFloats(v1, v2) >= 0
	case "&&":
		pred = truthy(v1) && truthy(v2)
	case "||":
		pred = truthy(v1) || truthy(v2)
	default:
		pred = false
	}
	if pred {
		return options.Fn()
	}
	return options.Inverse()
}

func toFloatOk(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func cmpFloats(a, b interface{}) float64 {
	fa, okA := toFloatOk(a)
	fb, okB := toFloatOk(b)
	if !okA || !okB {
		return 0
	}
	return fa - fb
}

func helperGetRemediation(description string, fixedIn interface{}) raymond.SafeString {
	idx := strings.Index(description, "## Remediation")
	if idx > -1 {
		return markdownToHTML(description[idx:])
	}
	if arr, ok := fixedIn.([]interface{}); ok && len(arr) > 0 {
		parts := make([]string, 0, len(arr))
		for _, x := range arr {
			parts = append(parts, fmt.Sprint(x))
		}
		return markdownToHTML("## Remediation\n Fixed in: " + strings.Join(parts, ", "))
	}
	return markdownToHTML(defaultRemediationText)
}

func helperSeverityLabel(severity interface{}, options *raymond.Options) string {
	_ = options
	s := fmt.Sprint(severity)
	if len(s) == 0 {
		return ""
	}
	return strings.ToUpper(s[:1])
}

func helperStartsWith(str, start string, options *raymond.Options) string {
	if strings.HasPrefix(str, start) {
		return options.Fn()
	}
	return options.Inverse()
}

func helperFormatDate(date interface{}) string {
	if date == nil {
		return "Unknown date"
	}
	s := strings.TrimSpace(fmt.Sprint(date))
	if s == "" {
		return "Unknown date"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, s)
	}
	if err != nil {
		return "Unknown date"
	}
	return t.UTC().Format("2006-01-02 15:04:05") + " GMT"
}

func helperFirstInitial(name interface{}) string {
	s := fmt.Sprint(name)
	if s == "" {
		return "?"
	}
	return strings.ToUpper(s[:1])
}
