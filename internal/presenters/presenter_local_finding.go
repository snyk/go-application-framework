package presenters

import (
	"bytes"
	"embed"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

type LocalFindingPresentation struct {
	Input       local_models.LocalFinding
	ScannedPath string
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

	sum := PrepareSummary(&p.Input.Summary, "", p.ScannedPath, "")

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
