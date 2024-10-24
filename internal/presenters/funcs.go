package presenters

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"text/template"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
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

func filterFinding(cmpFunc func(any) bool, findings []local_models.FindingResource) (filteredFindings []local_models.FindingResource) {
	for _, finding := range findings {
		if cmpFunc(finding) {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	return filteredFindings
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
	return fnMap
}

func getDefaultTemplateFuncMap(config configuration.Configuration) template.FuncMap {
	defaultMap := template.FuncMap{}
	defaultMap["getValueFromConfig"] = getFromConfig(config)
	defaultMap["sortFindingBy"] = sortFindingBy
	defaultMap["getFieldValueFrom"] = getFieldValueFrom
	defaultMap["filterFinding"] = filterFinding
	defaultMap["hasField"] = hasField
	defaultMap["notHasField"] = func(path string) func(obj any) bool {
		return func(obj any) bool {
			return !hasField(path)(obj)
		}
	}
	defaultMap["add"] = add
	defaultMap["sub"] = sub
	return defaultMap
}
