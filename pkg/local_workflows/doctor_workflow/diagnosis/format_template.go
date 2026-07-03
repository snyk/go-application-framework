package diagnosis

import (
	"embed"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/snyk/go-application-framework/internal/presenters"
)

// EnvDoctorTemplate overrides the embedded template files when set to a
// filesystem path, e.g. SNYK_DOCTOR_TEMPLATE=./diagnosis/templates/doctor.human.tmpl.
// This lets you iterate on the template without rebuilding the binary.
const EnvDoctorTemplate = "SNYK_DOCTOR_TEMPLATE"

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
func FormatTemplate(w io.Writer, report *DoctorReport) error {
	tmpl, err := template.New("doctor").Funcs(doctorFuncMap()).Parse("")
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	templateFiles := DefaultDoctorTemplateFiles
	if override := os.Getenv(EnvDoctorTemplate); override != "" {
		templateFiles = []string{override}
	}

	for _, filename := range templateFiles {
		data, err := readTemplateFile(filename)
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

// readTemplateFile reads a template from the embedded FS first; if that fails
// (e.g. the path is a filesystem override) it falls back to os.ReadFile.
func readTemplateFile(filename string) ([]byte, error) {
	data, err := embeddedTemplates.ReadFile(filename)
	if err != nil {
		data, err = os.ReadFile(filename)
	}
	return data, err
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

		// String helpers.
		"toUpper":    strings.ToUpper,
		"capitalize": cases.Title(language.English).String,
		"trimRight":  func(s string) string { return strings.TrimRight(s, " ") },
		"join":       strings.Join,
		"splitLines": func(s string) []string { return strings.Split(s, "\n") },

		// Color helpers for terminal output.
		"red":    func(s string) string { return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(s) },
		"green":  func(s string) string { return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(s) },
		"yellow": func(s string) string { return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(s) },
		"bold":   func(s string) string { return lipgloss.NewStyle().Bold(true).Render(s) },
		"severityIcon": func(sev Severity) string {
			switch sev {
			case SeverityError:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render("✗")
			case SeverityWarning:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render("!")
			default:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("✓")
			}
		},
		"severityColor": func(sev Severity, s string) string {
			switch sev {
			case SeverityError:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(s)
			case SeverityWarning:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(s)
			default:
				return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(s)
			}
		},

		// Domain helpers — expose existing functions so the template can
		// filter and group findings without Go-side layout code.
		"filterBySource": filterBySource,
		"extraSources":   extraSources,
		"sourceTitle":    sourceTitle,
	}
}
