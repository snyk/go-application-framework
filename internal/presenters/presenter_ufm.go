package presenters

import (
	"fmt"
	htmlTemplate "html/template"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

type UfmPresenter struct {
	TestPath         string
	Input            []testapi.TestResult
	config           configuration.Configuration
	writer           io.Writer
	runtimeinfo      runtimeinfo.RuntimeInfo
	templateImpl     map[string]TemplateImplFunction
	htmlTemplateImpl map[string]HTMLTemplateImplFunction
}

// HTMLTemplateImplFunction mirrors TemplateImplFunction but returns an *html/template.Template
type HTMLTemplateImplFunction func() (*htmlTemplate.Template, htmlTemplate.FuncMap, error)

var ApplicationSarifTemplatesUfm = []string{
	"templates/ufm.sarif.tmpl",
}

var ApplicationHTMLTemplatesUfm = []string{
	"templates/ufm.html.tmpl",
}

var DefaultTemplateFilesUfm = []string{
	"templates/ufm.human.tmpl",
}

type UfmPresenterOptions func(presentation *UfmPresenter)

func UfmWithRuntimeInfo(ri runtimeinfo.RuntimeInfo) UfmPresenterOptions {
	return func(p *UfmPresenter) {
		p.runtimeinfo = ri
	}
}

func NewUfmRenderer(results []testapi.TestResult, config configuration.Configuration, writer io.Writer, options ...UfmPresenterOptions) *UfmPresenter {
	p := &UfmPresenter{
		Input:  results,
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

				functionMapMimeType := getSarifTemplateFuncMap()
				return localFindingsTemplate, functionMapMimeType, nil
			},
		},
		htmlTemplateImpl: map[string]HTMLTemplateImplFunction{
			ApplicationHTMLMimeType: func() (*htmlTemplate.Template, htmlTemplate.FuncMap, error) {
				ufmTemplate, err := htmlTemplate.New(ApplicationHTMLMimeType).Parse("")
				if err != nil {
					return nil, nil, err
				}

				functionMapMimeType := getHTMLTemplateFuncMap()
				return ufmTemplate, functionMapMimeType, nil
			},
		},
	}

	for _, option := range options {
		option(p)
	}

	return p
}

func (p *UfmPresenter) getImplementationFromMimeType(mimeType string) (*template.Template, error) {
	functionMapGeneral := getDefaultTemplateFuncMap(p.config, p.runtimeinfo)

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

func (p *UfmPresenter) RegisterMimeType(mimeType string, implFactory TemplateImplFunction) error {
	if _, ok := p.templateImpl[mimeType]; ok {
		return fmt.Errorf("mimetype \"%s\" is already registered", mimeType)
	}
	if _, ok := p.htmlTemplateImpl[mimeType]; ok {
		return fmt.Errorf("mimetype \"%s\" is already registered", mimeType)
	}

	p.templateImpl[mimeType] = implFactory
	return nil
}

func (p *UfmPresenter) RenderTemplate(templateFiles []string, mimeType string) error {
	// Call renderHTMLTemplate() for HTML mime type
	if _, ok := p.htmlTemplateImpl[mimeType]; ok {
		return p.renderHTMLTemplate(templateFiles, mimeType)
	}

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

	writer := p.writer
	if strings.Contains(mimeType, "json") {
		writer = NewJsonWriter(writer, p.config.GetBool(CONFIG_JSON_STRIP_WHITESPACES))
	}

	err = mainTmpl.Execute(writer, struct {
		TestResults []testapi.TestResult
	}{
		TestResults: p.Input,
	})
	if err != nil {
		return err
	}
	return nil
}

// renderHTMLTemplate is the html/template counterpart of RenderTemplate
func (p *UfmPresenter) renderHTMLTemplate(templateFiles []string, mimeType string) error {
	ufmTemplate, err := p.getHTMLImplementationFromMimeType(mimeType)
	if err != nil {
		return err
	}

	err = loadHTMLTemplates(templateFiles, ufmTemplate)
	if err != nil {
		return err
	}

	mainTmpl := ufmTemplate.Lookup("main")
	if mainTmpl == nil {
		return fmt.Errorf("the template must contain a 'main'")
	}

	return mainTmpl.Execute(p.writer, struct {
		TestResults []testapi.TestResult
	}{
		TestResults: p.Input,
	})
}

func (p *UfmPresenter) getHTMLImplementationFromMimeType(mimeType string) (*htmlTemplate.Template, error) {
	functionMapGeneral := getDefaultTemplateFuncMap(p.config, p.runtimeinfo)

	ufmTemplate, functionMapMimeType, err := p.htmlTemplateImpl[mimeType]()
	if err != nil {
		return nil, err
	}

	if functionMapMimeType != nil {
		functionMapGeneral = utils.MergeMaps(functionMapGeneral, functionMapMimeType)
	}
	_ = ufmTemplate.Funcs(functionMapGeneral)

	return ufmTemplate, nil
}

// loadHTMLTemplates mirrors loadTemplates for the html/template tree
func loadHTMLTemplates(files []string, tmpl *htmlTemplate.Template) error {
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
