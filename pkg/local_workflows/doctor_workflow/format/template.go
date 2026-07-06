package format

import (
	"embed"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
)

//go:embed templates/*
var embeddedTemplates embed.FS

// DefaultDoctorTemplateFiles lists the embedded template files that compose the
// human-readable doctor report. Additional templates can be appended to
// customize or extend sections.
var DefaultDoctorTemplateFiles = []string{
	"templates/doctor.human.tmpl",
}

// FormatTemplate renders a DoctorReport through Go text/template files,
// following the same pattern used by the output workflow / UFM presenters.
func FormatTemplate(w io.Writer, report *diagnosis.DoctorReport) error {
	tmpl, err := template.New("doctor").Funcs(doctorFuncMap()).Parse("")
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	for _, filename := range DefaultDoctorTemplateFiles {
		data, err := embeddedTemplates.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed to read template file %s: %w", filename, err)
		}
		tmpl, err = tmpl.Parse(string(data))
		if err != nil {
			return fmt.Errorf("failed to parse template file %s: %w", filename, err)
		}
	}

	mainTmpl := tmpl.Lookup("main")
	if mainTmpl == nil {
		return fmt.Errorf("the template must contain a 'main'")
	}

	return mainTmpl.Execute(w, report)
}

// doctorFuncMap builds the template.FuncMap used by the doctor templates.
// It re-uses exported formatting functions from the presenters package and adds
// domain-specific helpers. All layout decisions live in the template itself.
func doctorFuncMap() template.FuncMap {
	return template.FuncMap{
		// Re-use formatting functions from the presenters package.
		"title":   presenters.RenderTitle,
		"divider": presenters.RenderDivider,
		"tip":     func(s string) string { return presenters.RenderTip(s + "\n") },

		// String helpers. toUpper accepts any so it works on named string types
		// (e.g. Kind) as well as plain strings.
		"toUpper":    func(v any) string { return strings.ToUpper(fmt.Sprint(v)) },
		"capitalize": cases.Title(language.English).String,
		"trimRight":  func(s string) string { return strings.TrimRight(s, " ") },
		"join":       strings.Join,
		"splitLines": func(s string) []string { return strings.Split(s, "\n") },

		// Color helpers for terminal output.
		"red":    func(s string) string { return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(s) },
		"green":  func(s string) string { return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(s) },
		"yellow": func(s string) string { return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(s) },
		"bold":   func(s string) string { return lipgloss.NewStyle().Bold(true).Render(s) },
		"severityIcon": func(sev diagnosis.Severity) string {
			switch sev {
			case diagnosis.SeverityError:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render("✗")
			case diagnosis.SeverityWarning:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render("!")
			default:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("✓")
			}
		},
		"severityColor": func(sev diagnosis.Severity, s string) string {
			switch sev {
			case diagnosis.SeverityError:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(s)
			case diagnosis.SeverityWarning:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(s)
			default:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(s)
			}
		},
	}
}
