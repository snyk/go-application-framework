package presenters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

func (p *UfmPresenter) renderFullTOON(ctx context.Context, templateFiles []string) error {
	document, err := p.buildFullTOONDocument(ctx)
	if err != nil {
		return err
	}

	toonTemplate, err := p.getImplementationFromMimeType(ApplicationTOONMimeType)
	if err != nil {
		return err
	}
	toonTemplate.Funcs(getToonContextTemplateFuncMap(ctx))
	if loadErr := loadTemplates(templateFiles, toonTemplate); loadErr != nil {
		return loadErr
	}

	state := templateDict("Envelope", document, "Fatal", false, "Full", true)
	for _, result := range p.Input {
		if !fullTOONNeedsDiagnostics(result) {
			continue
		}

		issues, issuesErr := testapi.NewIssuesFromTestResult(ctx, result)
		if issuesErr != nil {
			return fmt.Errorf("convert test result to issues: %w", issuesErr)
		}
		var diagnostics bytes.Buffer
		if executeErr := toonTemplate.ExecuteTemplate(&diagnostics, "toonDiagnostics", templateDict(
			"State", state,
			"Result", result,
			"Issues", issues,
		)); executeErr != nil {
			return executeErr
		}
	}
	for _, key := range []string{"findings", "sca", "secrets"} {
		if values, ok := document[key].([]any); ok && len(values) == 0 {
			delete(document, key)
		}
	}

	var toonOutput bytes.Buffer
	if executeErr := toonTemplate.ExecuteTemplate(&toonOutput, "toonDocument", document); executeErr != nil {
		return executeErr
	}
	_, err = io.Copy(p.writer, bytes.NewReader(toonOutput.Bytes()))
	return err
}

func (p *UfmPresenter) buildFullTOONDocument(ctx context.Context) (map[string]any, error) {
	sarifTemplate, err := p.getImplementationFromMimeType(ApplicationSarifMimeType)
	if err != nil {
		return nil, err
	}
	sarifTemplate.Funcs(getSarifContextTemplateFuncMap(ctx))
	if loadErr := loadTemplates(ApplicationSarifTemplatesUfm, sarifTemplate); loadErr != nil {
		return nil, loadErr
	}

	var sarifOutput bytes.Buffer
	if executeErr := sarifTemplate.ExecuteTemplate(&sarifOutput, "main", struct {
		TestResults []testapi.TestResult
	}{
		TestResults: p.Input,
	}); executeErr != nil {
		return nil, executeErr
	}

	document, err := decodeFullTOONDocument(sarifOutput.Bytes())
	if err != nil {
		return nil, err
	}
	delete(document, "$schema")
	delete(document, "version")
	if runs, ok := document["runs"].([]any); ok {
		for _, run := range runs {
			if run, ok := run.(map[string]any); ok {
				delete(run, "automationDetails")
			}
		}
	}
	return document, nil
}

func fullTOONNeedsDiagnostics(result testapi.TestResult) bool {
	state := result.GetExecutionState()
	if state != "" && state != testapi.TestExecutionStatesFinished {
		return true
	}
	if errors := result.GetErrors(); errors != nil && len(*errors) > 0 {
		return true
	}
	if warnings := result.GetWarnings(); warnings != nil && len(*warnings) > 0 {
		return true
	}
	return false
}

func decodeFullTOONDocument(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode SARIF document: %w", err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode SARIF document: multiple JSON values")
		}
		return nil, fmt.Errorf("decode SARIF document: trailing JSON: %w", err)
	}
	return document, nil
}
