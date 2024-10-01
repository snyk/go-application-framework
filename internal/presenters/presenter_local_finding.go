package presenters

import "github.com/snyk/go-application-framework/pkg/local_workflows/local_models"

type LocalFindingPresentation struct {
	Input local_models.LocalFinding
}

func LocalFindingPresenter(doc local_models.LocalFinding) *LocalFindingPresentation {
	return &LocalFindingPresentation{
		Input: doc,
	}
}

func (p *LocalFindingPresentation) Render() (string, error) {
	return "", nil
}
