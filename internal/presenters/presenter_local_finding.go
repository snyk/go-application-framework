package presenters

import (
	"bytes"
	"embed"
	"errors"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

type LocalFindingPresentation struct {
	Input             local_models.LocalFinding
	ScannedPath       string
	SeverityThreshold string
}

// TemplatePathsStruct holds the paths to the templates.
type TemplatePathsStruct struct {
	LocalFindingTemplate     string
	FindingComponentTemplate string
}

// TemplatePaths is an instance of TemplatePathsStruct with the template paths.
var TemplatePaths = TemplatePathsStruct{
	LocalFindingTemplate:     "templates/local_finding.tmpl",
	FindingComponentTemplate: "templates/finding.component.tmpl",
}

// contains checks if a string is in a slice of strings.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func FilterBySeverityThreshold(severity_threshold string, findings_model *local_models.LocalFinding) error {
	if severity_threshold == "" {
		return nil
	}
	var severity_filters = map[string][]string{
		"low":      {"low", "medium", "high", "critical"},
		"medium":   {"medium", "high", "critical"},
		"high":     {"high", "critical"},
		"critical": {"critical"},
	}
	allowed_severities, ok := severity_filters[severity_threshold]
	if !ok {
		return errors.New("Invalid severity threshold")
	}

	filtered_findings := []local_models.FindingResource{}
	for _, finding := range findings_model.Findings {
		if contains(allowed_severities, string(finding.Attributes.Rating.Severity.Value)) {
			filtered_findings = append(filtered_findings, finding)
		}
	}
	findings_model.Findings = filtered_findings

	return nil
}

func LocalFindingPresenter(doc local_models.LocalFinding, scanned_path string) *LocalFindingPresentation {
	return &LocalFindingPresentation{
		Input:       doc,
		ScannedPath: scanned_path,
	}
}

//go:embed templates/*
var embeddedFiles embed.FS

func LoadTemplates(files []string, tmpl *template.Template) error {
	for _, file := range files {
		data, err := embeddedFiles.ReadFile(file)
		if err != nil {
			return err
		}
		tmpl, err = tmpl.Parse(string(data))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *LocalFindingPresentation) Render() (string, error) {
	local_findings_template, err := template.New("local_finding").Parse("")
	if err != nil {
		return "", err
	}
	AddTemplateFuncs(local_findings_template)
	err = LoadTemplates([]string{
		TemplatePaths.LocalFindingTemplate,
		TemplatePaths.FindingComponentTemplate,
	}, local_findings_template)
	if err != nil {
		return "", err
	}

	// filter findings
	err = FilterBySeverityThreshold(p.SeverityThreshold, &p.Input)
	if err != nil {
		return "", err
	}

	// TODO: Add org and scanned path to the summary
	sum := PrepareSummary(&p.Input.Summary, "", p.ScannedPath, p.SeverityThreshold)

	buf := new(bytes.Buffer)
	main_tmpl := local_findings_template.Lookup("main")

	err = main_tmpl.Execute(buf, struct {
		Summary SummaryData
		Results local_models.LocalFinding
	}{
		Summary: sum,
		Results: p.Input,
	})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
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

func AddTemplateFuncs(t *template.Template) {
	var fnMap = template.FuncMap{
		"box": func(s string) string {
			return boxStyle.Render(s)
		},
		"renderToString": renderTemplateToString(t),
	}
	t.Funcs(fnMap)
}
