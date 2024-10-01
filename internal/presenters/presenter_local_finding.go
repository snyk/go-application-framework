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

func (p *LocalFindingPresentation) Render() (string, error) {
	data, err := os.ReadFile("./templates/local_finding.tmpl")
	if err != nil {
		return "", err
	}

	local_findings_template, err := template.New("local_finding").Parse(string(data))
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	main_tmpl := local_findings_template.Lookup("main")
	err = main_tmpl.Execute(buf, p)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
