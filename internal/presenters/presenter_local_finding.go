package presenters

import (
	"embed"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

const DefaultMimeType = "text/cli"
const NoneMimeType = "unknown"
const ApplicationJSONMimeType = "application/json"
const ApplicationSarifMimeType = content_type.SARIF_JSON

//go:embed templates/*
var embeddedFiles embed.FS

type TemplateImplFunction func() (*template.Template, template.FuncMap, error)

type LocalFindingPresenter struct {
	TestPath     string
	Input        *local_models.LocalFinding
	config       configuration.Configuration
	writer       io.Writer
	templateImpl map[string]TemplateImplFunction
}

// DefaultTemplateFiles is an instance of TemplatePathsStruct with the template paths.
var DefaultTemplateFiles = []string{
	"templates/local_finding.tmpl",
	"templates/finding.component.tmpl",
}

var ApplicationSarifTemplates = []string{
	"templates/local_finding.sarif.tmpl",
}

type LocalFindingPresenterOptions func(presentation *LocalFindingPresenter)

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

				functionMapMimeType := getCliTemplateFuncMap(localFindingsTemplate)
				return localFindingsTemplate, functionMapMimeType, nil
			},
			ApplicationSarifMimeType: func() (*template.Template, template.FuncMap, error) {
				localFindingsTemplate, err := template.New(ApplicationSarifMimeType).Parse("")
				if err != nil {
					return nil, nil, err
				}

				functionMapMimeType := getCliTemplateFuncMap(localFindingsTemplate)
				return localFindingsTemplate, functionMapMimeType, nil
			},
		},
	}

	for _, option := range options {
		option(p)
	}

	return p
}

func (p *LocalFindingPresenter) getImplementationFromMimeType(mimeType string) (*template.Template, error) {
	functionMapGeneral := getDefaultTemplateFuncMap(p.config)

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

	mainTmpl := localFindingsTemplate.Lookup("main")
	if mainTmpl == nil {
		return fmt.Errorf("the template must contain a 'main'")
	}

	err = mainTmpl.Execute(p.writer, struct {
		Results []*local_models.LocalFinding
	}{
		Results: []*local_models.LocalFinding{p.Input},
	})
	if err != nil {
		return err
	}
	return nil
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
