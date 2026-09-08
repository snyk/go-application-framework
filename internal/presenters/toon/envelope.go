package toon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// PrepareResults returns normalized JSON values for the TOON template.
func PrepareResults(ctx context.Context, results []testapi.TestResult) (any, error) {
	envelope, err := buildEnvelope(ctx, results)
	if err != nil {
		return nil, err
	}
	return jsonValue(envelope)
}

func buildEnvelope(ctx context.Context, results []testapi.TestResult) (map[string]any, error) {
	encoded := make([]any, len(results))
	for i, result := range results {
		if result == nil {
			return nil, fmt.Errorf("test result at index %d is nil", i)
		}
		item, err := buildResultEnvelope(ctx, result)
		if err != nil {
			return nil, err
		}
		encoded[i] = item
	}
	return map[string]any{"results": encoded}, nil
}

func buildResultEnvelope(ctx context.Context, result testapi.TestResult) (map[string]any, error) {
	findings, _, err := result.Findings(ctx)
	if err != nil {
		return nil, fmt.Errorf("findings: %w", err)
	}

	if findings == nil {
		findings = []testapi.FindingData{}
	}

	return map[string]any{
		"testId":            result.GetTestID(),
		"testConfiguration": result.GetTestConfiguration(),
		"executionState":    result.GetExecutionState(),
		"effectiveSummary":  result.GetEffectiveSummary(),
		"rawSummary":        result.Get(testapi.TestResultRawSummary),
		"passFail":          result.GetPassFail(),
		"outcomeReason":     result.GetOutcomeReason(),
		"errors":            result.GetErrors(),
		"warnings":          result.GetWarnings(),
		"testSubject":       result.Get(testapi.TestResultTestSubject),
		"findings":          findings,
	}, nil
}

func jsonValue(value any) (any, error) {
	if value == nil {
		return nullJSONValue(), nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if string(payload) == "null" {
		return nullJSONValue(), nil
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func nullJSONValue() any {
	return nil
}
