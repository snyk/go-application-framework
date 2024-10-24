package presenters

import (
	"bytes"
	"embed"
	"errors"
	"slices"
	"strings"
	"text/template"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

type LocalFindingPresenter struct {
	ShowIgnored      bool
	Input            local_models.LocalFinding
	OrgName          string
	TestPath         string
	SeverityMinLevel string
}

// TemplatePathsStruct holds the paths to the templates.
type TemplatePathsStruct struct {
	LocalFindingTemplate     string
	FindingComponentTemplate string
}

type PresentationFindingResource struct {
	local_models.FindingResource
}

func (pfr *PresentationFindingResource) IsIgnored() bool {
	return pfr.Attributes.Suppression != nil
}

type FilteredFindings struct {
	OpenFindings    []*PresentationFindingResource
	IgnoredFindings []*PresentationFindingResource
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

type LocalFindingPresenterOptions func(presentation *LocalFindingPresenter)

func WithLocalFindingsIgnoredIssues(showIgnored bool) LocalFindingPresenterOptions {
	return func(p *LocalFindingPresenter) {
		p.ShowIgnored = showIgnored
	}
}

func WithLocalFindingsOrg(org string) LocalFindingPresenterOptions {
	return func(p *LocalFindingPresenter) {
		p.OrgName = org
	}
}

func WithLocalFindingsTestPath(testPath string) LocalFindingPresenterOptions {
	return func(p *LocalFindingPresenter) {
		p.TestPath = testPath
	}
}

func WithLocalFindingsSeverityLevel(severityMinLevel string) LocalFindingPresenterOptions {
	return func(p *LocalFindingPresenter) {
		p.SeverityMinLevel = severityMinLevel
	}
}

func LocalFindingsTestResults(localFindingsDoc local_models.LocalFinding, options ...LocalFindingPresenterOptions) *LocalFindingPresenter {
	p := &LocalFindingPresenter{
		ShowIgnored:      false,
		Input:            localFindingsDoc,
		OrgName:          "",
		TestPath:         "",
		SeverityMinLevel: "",
	}
	for _, option := range options {
		option(p)
	}

	return p
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

func (p *LocalFindingPresenter) Render() (string, error) {
	localFindingsTemplate, err := template.New("local_finding").Parse("")
	if err != nil {
		return "", err
	}
	AddTemplateFuncs(localFindingsTemplate)
	err = LoadTemplates([]string{
		TemplatePaths.LocalFindingTemplate,
		TemplatePaths.FindingComponentTemplate,
	}, localFindingsTemplate)
	if err != nil {
		return "", err
	}

	// filter findings
	err = FilterBySeverityThreshold(p.SeverityMinLevel, &p.Input)
	if err != nil {
		return "", err
	}

	sum := PrepareSummary(&p.Input.Summary, p.OrgName, p.TestPath, p.SeverityMinLevel)

	buf := new(bytes.Buffer)
	mainTmpl := localFindingsTemplate.Lookup("main")

	filteredFindings := filterOutIgnoredFindings(p.Input.Findings, p.ShowIgnored, []string{"low", "medium", "high"})

	err = mainTmpl.Execute(buf, struct {
		Summary         SummaryData `json:"summary"`
		OpenFindings    []*PresentationFindingResource
		IgnoredFindings []*PresentationFindingResource
		ShowIgnored     bool
		ShowDivider     bool
		SeverityFilter  string
	}{
		Summary:         sum,
		OpenFindings:    filteredFindings.OpenFindings,
		IgnoredFindings: filteredFindings.IgnoredFindings,
		ShowIgnored:     p.ShowIgnored,
		ShowDivider:     shouldShowDivider(filteredFindings, p.ShowIgnored),
		SeverityFilter:  p.SeverityMinLevel,
	})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func shouldShowDivider(findings FilteredFindings, showIgnored bool) bool {
	hasFindings := len(findings.OpenFindings) > 0 && len(findings.IgnoredFindings) > 0
	return hasFindings || showIgnored
}

func sortFindings(findings []*PresentationFindingResource, order []string) []*PresentationFindingResource {
	result := make([]*PresentationFindingResource, 0, len(findings))

	result = append(result, findings...)

	slices.SortFunc(result, func(a, b *PresentationFindingResource) int {
		if a.Attributes.Rating.Severity.Value != b.Attributes.Rating.Severity.Value {
			return slices.Index(order, string(a.Attributes.Rating.Severity.Value)) - slices.Index(order, string(b.Attributes.Rating.Severity.Value))
		}

		return 0
	})

	return result
}

func filterOutIgnoredFindings(findings []local_models.FindingResource, showIgnored bool, sortOrder []string) (filtered FilteredFindings) {
	for _, finding := range findings {
		if finding.Attributes.Suppression == nil {
			filtered.OpenFindings = append(filtered.OpenFindings, &PresentationFindingResource{FindingResource: finding})
		} else if showIgnored {
			filtered.IgnoredFindings = append(filtered.IgnoredFindings, &PresentationFindingResource{FindingResource: finding})
		}
	}

	filtered.OpenFindings = sortFindings(filtered.OpenFindings, sortOrder)
	filtered.IgnoredFindings = sortFindings(filtered.IgnoredFindings, sortOrder)
	return filtered
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

func renderWithSeverity(severity string) string {
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

func bold(s string) string {
	return lipgloss.NewStyle().Bold(true).Render(s)
}

func AddTemplateFuncs(t *template.Template) {
	var fnMap = template.FuncMap{
		"box": func(s string) string {
			return boxStyle.Render(s)
		},
		"renderToString":        renderTemplateToString(t),
		"toUpperCase":           strings.ToUpper,
		"renderInSeverityColor": renderWithSeverity,
		"bold":                  bold,
		"tip": func(s string) string {
			return RenderTip(s + "\n")
		},
		"divider": RenderDivider,
		"title":   RenderTitle,
	}
	t.Funcs(fnMap)
}
