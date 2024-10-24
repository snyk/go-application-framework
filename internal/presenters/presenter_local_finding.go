package presenters

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/template"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

const DefaultMimeType = "text/cli"
const NoneMimeType = "unknown"
const ApplicationJSONMimeType = "application/json"

//go:embed templates/*
var embeddedFiles embed.FS

type TemplateImplFunction func() (*template.Template, template.FuncMap, error)

type LocalFindingPresenter struct {
	ShowIgnored      bool
	Input            *local_models.LocalFinding
	OrgName          string
	TestPath         string
	SeverityMinLevel string
	config           configuration.Configuration
	writer           io.Writer
	templateImpl     map[string]TemplateImplFunction
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

// DefaultTemplateFiles is an instance of TemplatePathsStruct with the template paths.
var DefaultTemplateFiles = []string{
	"templates/local_finding.tmpl",
	"templates/finding.component.tmpl",
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

func NewLocalFindingsRenderer(localFindingsDoc *local_models.LocalFinding, config configuration.Configuration, writer io.Writer, options ...LocalFindingPresenterOptions) *LocalFindingPresenter {
	p := &LocalFindingPresenter{
		Input:  localFindingsDoc,
		config: config,
		writer: writer,
		templateImpl: map[string]TemplateImplFunction{
			NoneMimeType: func() (*template.Template, template.FuncMap, error) {
				localFindingsTemplate, err := template.New(NoneMimeType).Parse("")
				if err != nil {
					return nil, nil, err
				}
				return localFindingsTemplate, nil, nil
			},
			DefaultMimeType: func() (*template.Template, template.FuncMap, error) {
				localFindingsTemplate, err := template.New(DefaultMimeType).Parse("")
				if err != nil {
					return nil, nil, err
				}

				functionMapMimeType := getTemplateFuncsCLI(localFindingsTemplate)
				return localFindingsTemplate, functionMapMimeType, nil
			},
		},
	}

	for _, option := range options {
		option(p)
	}

	return p
}

func loadTemplates(files []string, tmpl *template.Template) error {
	if len(files) == 0 {
		return fmt.Errorf("a template file must be specified")
	}

	for _, filename := range files {
		data, err := embeddedFiles.ReadFile(filename)
		if err != nil {
			data, err = os.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("failed to read template file %s", filename)
			}
		}
		tmpl, err = tmpl.Parse(string(data))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *LocalFindingPresenter) getImplementationFromMimeType(mimeType string) (*template.Template, error) {
	functionMapGeneral := getDefaultTemplateFunctions(p.config)

	if _, ok := p.templateImpl[mimeType]; !ok {
		mimeType = NoneMimeType
	}

	localFindingsTemplate, functionMapMimeType, err := p.templateImpl[mimeType]()
	if err != nil {
		return nil, err
	}

	if functionMapMimeType != nil {
		functionMapGeneral = utils.MergeMaps(functionMapGeneral, functionMapMimeType)
	}
	_ = localFindingsTemplate.Funcs(functionMapGeneral)

	return localFindingsTemplate, nil
}

func (p *LocalFindingPresenter) RegisterMimeType(mimeType string, implFactory TemplateImplFunction) error {
	if _, ok := p.templateImpl[mimeType]; ok {
		return fmt.Errorf("mimetype \"%s\" is already registered", mimeType)
	}

	p.templateImpl[mimeType] = implFactory
	return nil
}

func (p *LocalFindingPresenter) RenderTemplate(templateFiles []string, mimeType string) error {
	// mimetype specific
	localFindingsTemplate, err := p.getImplementationFromMimeType(mimeType)
	if err != nil {
		return err
	}

	// load files
	err = loadTemplates(templateFiles, localFindingsTemplate)
	if err != nil {
		return err
	}

	sum := PrepareSummary(&p.Input.Summary, p.OrgName, p.TestPath, p.SeverityMinLevel)

	mainTmpl := localFindingsTemplate.Lookup("main")
	if mainTmpl == nil {
		return fmt.Errorf("the template must contain a 'main'")
	}

	filteredFindings := filterOutIgnoredFindings(p.Input.Findings, p.ShowIgnored, []string{"low", "medium", "high"})

	err = mainTmpl.Execute(p.writer, struct {
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
		return err
	}
	return nil
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

func add(a, b int) int {
	return a + b
}

func sub(a, b int) int {
	return a - b
}

func getTemplateFuncsCLI(tmpl *template.Template) template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["box"] = func(s string) string { return boxStyle.Render(s) }
	fnMap["toUpperCase"] = strings.ToUpper
	fnMap["renderInSeverityColor"] = renderWithSeverity
	fnMap["bold"] = bold
	fnMap["tip"] = func(s string) string {
		return RenderTip(s + "\n")
	}
	fnMap["divider"] = RenderDivider
	fnMap["title"] = RenderTitle
	fnMap["renderToString"] = renderTemplateToString(tmpl)
	return fnMap
}

func getDefaultTemplateFunctions(config configuration.Configuration) template.FuncMap {
	defaultMap := template.FuncMap{}
	defaultMap["getValueFromConfig"] = config.Get
	defaultMap["add"] = add
	defaultMap["sub"] = sub
	return defaultMap
}
