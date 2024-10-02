package presenters

import (
	"bytes"
	"os"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

type LocalFindingPresentation struct {
	Input       local_models.LocalFinding
	ScannedPath string
}

func LocalFindingPresenter(doc local_models.LocalFinding, scanned_path string) *LocalFindingPresentation {
	return &LocalFindingPresentation{
		Input:       doc,
		ScannedPath: scanned_path,
	}
}

func loadTemplates(files []string, tmpl *template.Template) error {
	for _, file := range files {
		data, err := os.ReadFile(file)
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
	var templatePaths = []string{
		"./templates/local_finding.tmpl",
		"./templates/finding.component.tmpl",
	}

	local_findings_template, _ := template.New("local_finding").Parse("")
	addTemplateFuncs(local_findings_template)
	err := loadTemplates(templatePaths, local_findings_template)
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

func addTemplateFuncs(t *template.Template) {
	var fnMap = template.FuncMap{
		"box": func(s string) string {
			return boxStyle.Render(s)
		},
		"renderToString": renderTemplateToString(t),
		"renderFinding": func(finding local_models.FindingResource) string {
			output, err := renderTemplateToString(t)("finding", finding)
			if err != nil {
				return ""
			}
			return output
		},
	}
	t.Funcs(fnMap)
}
