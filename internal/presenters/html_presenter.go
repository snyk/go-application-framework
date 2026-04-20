package presenters

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mailgun/raymond/v2"
)

// HTMLReportKind selects which snyk-to-html template set to use.
type HTMLReportKind string

const (
	HTMLReportKindCode HTMLReportKind = "code"
	HTMLReportKindSCA  HTMLReportKind = "sca"
)

// HTMLReportRenderer renders snyk-to-html compatible reports using embedded .hbs templates.
type HTMLReportRenderer struct {
	kind        HTMLReportKind
	tpl         *raymond.Template
	summaryOnly bool
	customPath  string
}

// HTMLReportRendererOption configures HTMLReportRenderer.
type HTMLReportRendererOption func(*htmlPresenterConfig)

type htmlPresenterConfig struct {
	customTemplate string
	summaryOnly    bool
}

// WithHTMLReportCustomTemplate mirrors snyk-to-html -t/--template (main template only; partials stay embedded).
func WithHTMLReportCustomTemplate(path string) HTMLReportRendererOption {
	return func(c *htmlPresenterConfig) {
		c.customTemplate = path
	}
}

// WithHTMLReportSummaryOnly sets showSummaryOnly on template data (like snyk-to-html -s).
func WithHTMLReportSummaryOnly(summary bool) HTMLReportRendererOption {
	return func(c *htmlPresenterConfig) {
		c.summaryOnly = summary
	}
}

func partialNamesForKind(kind HTMLReportKind) []string {
	switch kind {
	case HTMLReportKindCode:
		return []string{"inline-css", "inline-js", "header", "metatable-css", "metatable", "code-snip"}
	case HTMLReportKindSCA:
		return []string{
			"inline-css", "header", "metatable-css", "metatable", "inline-js",
			"vuln-card", "remediation-css", "actionable-remediations",
		}
	default:
		return nil
	}
}

func templateBaseDir(kind HTMLReportKind) string {
	switch kind {
	case HTMLReportKindCode:
		return "templates/html/code"
	case HTMLReportKindSCA:
		return "templates/html/sca"
	default:
		return ""
	}
}

// NewHTMLReportRenderer builds a compiled raymond template with helpers and partials.
func NewHTMLReportRenderer(kind HTMLReportKind, opts ...HTMLReportRendererOption) (*HTMLReportRenderer, error) {
	var cfg htmlPresenterConfig
	for _, o := range opts {
		o(&cfg)
	}
	base := templateBaseDir(kind)
	if base == "" {
		return nil, fmt.Errorf("unknown HTMLReportKind: %q", kind)
	}
	mainRel := filepath.ToSlash(filepath.Join(base, "test-report.hbs"))
	var mainSrc []byte
	var err error
	if cfg.customTemplate != "" {
		mainSrc, err = os.ReadFile(cfg.customTemplate)
	} else {
		mainSrc, err = embeddedFiles.ReadFile(mainRel)
	}
	if err != nil {
		return nil, fmt.Errorf("read main template: %w", err)
	}
	tpl, err := raymond.Parse(string(mainSrc))
	if err != nil {
		return nil, fmt.Errorf("parse main template: %w", err)
	}
	registerHTMLHelpers(tpl)
	for _, name := range partialNamesForKind(kind) {
		partialRel := filepath.ToSlash(filepath.Join(base, fmt.Sprintf("test-report.%s.hbs", name)))
		b, err := embeddedFiles.ReadFile(partialRel)
		if err != nil {
			return nil, fmt.Errorf("read partial %q: %w", name, err)
		}
		tpl.RegisterPartial(name, string(b))
	}
	return &HTMLReportRenderer{
		kind:        kind,
		tpl:         tpl,
		summaryOnly: cfg.summaryOnly,
		customPath:  cfg.customTemplate,
	}, nil
}

// Render writes HTML for the given JSON (SARIF for Code, legacy SCA JSON for Open Source).
func (p *HTMLReportRenderer) Render(w io.Writer, rawJSON []byte) error {
	var data map[string]any
	var err error
	switch p.kind {
	case HTMLReportKindCode:
		data, err = PreprocessCodeSARIF(rawJSON, p.summaryOnly)
	case HTMLReportKindSCA:
		data, err = PreprocessLegacySCAJSON(rawJSON, p.summaryOnly)
	default:
		return fmt.Errorf("unknown report kind")
	}
	if err != nil {
		return err
	}
	if p.kind == HTMLReportKindSCA {
		ensureSCAKeys(data)
	}
	out, err := p.tpl.Exec(data)
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	_, err = io.WriteString(w, out)
	return err
}

func ensureSCAKeys(data map[string]any) {
	// metatable partial expects certain fields; merged JSON may omit nils.
	if _, ok := data["projectName"]; !ok {
		data["projectName"] = nil
	}
	if _, ok := data["path"]; !ok {
		data["path"] = nil
	}
	if _, ok := data["displayTargetFile"]; !ok {
		data["displayTargetFile"] = nil
	}
	if _, ok := data["packageManager"]; !ok {
		data["packageManager"] = nil
	}
	if _, ok := data["paths"]; !ok {
		data["paths"] = nil
	}
}
