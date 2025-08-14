package unified_presenters

import (
	"embed"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

// DefaultMimeType is the default mime type for the presenter.
const DefaultMimeType = "text/cli"

// NoneMimeType is the mime type for when no mime type is specified.
const NoneMimeType = "unknown"

// ApplicationJSONMimeType is the mime type for application/json.
const ApplicationJSONMimeType = "application/json"

// ConfigJSONStripWhitespaces is the configuration key to strip whitespaces from JSON output.
const ConfigJSONStripWhitespaces = "internal_json_no_whitespaces"

//go:embed templates/*
var embeddedFiles embed.FS

// TemplateImplFunction is a function that returns a template, a function map, and an error.
type TemplateImplFunction func() (*template.Template, template.FuncMap, error)

// DefaultTemplateFiles is an instance of TemplatePathsStruct with the template paths.
var DefaultTemplateFiles = []string{
	"templates/unified_finding.tmpl",
	"templates/finding.component.tmpl",
}

// UnifiedProjectResult holds the findings and summary for a single project from the unified flow.
type UnifiedProjectResult struct {
	Findings             []testapi.FindingData
	Summary              *json_schemas.TestSummary
	DependencyCount      int
	PackageManager       string
	ProjectName          string
	DisplayTargetFile    string
	UniqueCount          int
	VulnerablePathsCount int
}

// SummaryPayload is a wrapper for the test summary and additional metadata needed for the unified output.
type SummaryPayload struct {
	Summary              *json_schemas.TestSummary `json:"summary"`
	DependencyCount      int                       `json:"dependencyCount"`
	PackageManager       string                    `json:"packageManager"`
	ProjectName          string                    `json:"projectName"`
	DisplayTargetFile    string                    `json:"displayTargetFile"`
	UniqueCount          int32                     `json:"uniqueCount"`
	VulnerablePathsCount int                       `json:"vulnerablePathsCount"`
}

// UnifiedFindingPresenter is responsible for rendering unified findings data.
type UnifiedFindingPresenter struct {
	Input        []*UnifiedProjectResult
	config       configuration.Configuration
	writer       io.Writer
	runtimeinfo  runtimeinfo.RuntimeInfo
	templateImpl map[string]TemplateImplFunction
}

// UnifiedFindingPresenterOptions configures the UnifiedFindingPresenter.
type UnifiedFindingPresenterOptions func(presentation *UnifiedFindingPresenter)

// WithUnifiedRuntimeInfo adds runtime information to the presenter.
func WithUnifiedRuntimeInfo(ri runtimeinfo.RuntimeInfo) UnifiedFindingPresenterOptions {
	return func(p *UnifiedFindingPresenter) {
		p.runtimeinfo = ri
	}
}

// NewUnifiedFindingsRenderer creates a new presenter for unified findings.
// Note: This new renderer works directly with the testapi.FindingData model.
// The templates used will need to be compatible with this data structure.
func NewUnifiedFindingsRenderer(
	unifiedFindingsDoc []*UnifiedProjectResult,
	config configuration.Configuration,
	writer io.Writer,
	options ...UnifiedFindingPresenterOptions,
) *UnifiedFindingPresenter {
	p := &UnifiedFindingPresenter{
		Input:  unifiedFindingsDoc,
		config: config,
		writer: writer,
		templateImpl: map[string]TemplateImplFunction{
			// This is duplicated from NewLocalFindingsRenderer. A refactor could consolidate this.
			NoneMimeType: func() (*template.Template, template.FuncMap, error) {
				tmpl, err := template.New(NoneMimeType).Parse("")
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse template for %s: %w", NoneMimeType, err)
				}
				return tmpl, nil, nil
			},
			DefaultMimeType: func() (*template.Template, template.FuncMap, error) {
				tmpl, err := template.New(DefaultMimeType).Parse("")
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse template for %s: %w", DefaultMimeType, err)
				}
				functionMapMimeType := getCliTemplateFuncMap(tmpl)
				return tmpl, functionMapMimeType, nil
			},
		},
	}

	for _, option := range options {
		option(p)
	}

	return p
}

// getImplementationFromMimeType gets the template implementation for a given MIME type.
func (p *UnifiedFindingPresenter) getImplementationFromMimeType(mimeType string) (*template.Template, error) {
	functionMapGeneral := getDefaultTemplateFuncMap(p.config, p.runtimeinfo)

	if _, ok := p.templateImpl[mimeType]; !ok {
		mimeType = NoneMimeType
	}

	tmpl, functionMapMimeType, err := p.templateImpl[mimeType]()
	if err != nil {
		return nil, err
	}

	if functionMapMimeType != nil {
		functionMapGeneral = mergeMaps(functionMapGeneral, functionMapMimeType)
	}
	_ = tmpl.Funcs(functionMapGeneral)

	return tmpl, nil
}

// RenderTemplate renders the template with the given files and MIME type.
func (p *UnifiedFindingPresenter) RenderTemplate(templateFiles []string, mimeType string) error {
	tmpl, err := p.getImplementationFromMimeType(mimeType)
	if err != nil {
		return err
	}

	err = loadTemplates(templateFiles, tmpl)
	if err != nil {
		return err
	}

	mainTmpl := tmpl.Lookup("main")
	if mainTmpl == nil {
		return fmt.Errorf("the template must contain a 'main'")
	}

	writer := p.writer
	if strings.Contains(mimeType, "json") {
		writer = NewJSONWriter(writer, p.config.GetBool(ConfigJSONStripWhitespaces))
	}

	executeErr := mainTmpl.Execute(writer, struct {
		Results []*UnifiedProjectResult
	}{
		Results: p.Input,
	})
	if executeErr != nil {
		return fmt.Errorf("failed to execute template: %w", executeErr)
	}
	return nil
}

// loadTemplates loads template files into the given template.
func loadTemplates(files []string, tmpl *template.Template) error {
	if len(files) == 0 {
		return fmt.Errorf("a template file must be specified")
	}

	for _, filename := range files {
		data, err := os.ReadFile(filename)
		if err != nil {
			data, err = embeddedFiles.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("failed to read template file %s", filename)
			}
		}
		tmpl, err = tmpl.Parse(string(data))
		if err != nil {
			return fmt.Errorf("failed to parse template file %s: %w", filename, err)
		}
	}
	return nil
}

// mergeMaps merges two maps, with values from mapB taking precedence over mapA.
func mergeMaps[K comparable, V any](mapA, mapB map[K]V) map[K]V {
	result := maps.Clone(mapA)

	for k, v := range mapB {
		result[k] = v
	}

	return result
}
