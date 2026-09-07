package toon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// EncodeResults builds the contract envelope from native test results and renders TOON.
func EncodeResults(ctx context.Context, results []testapi.TestResult) ([]byte, error) {
	envelope, err := buildEnvelope(ctx, results)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return EncodeJSON(payload)
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

	findingValues := make([]any, len(findings))
	for i, finding := range findings {
		value, marshalErr := encodeFinding(finding)
		if marshalErr != nil {
			return nil, marshalErr
		}
		findingValues[i] = value
	}

	rawSummary, err := jsonValue(result.Get(testapi.TestResultRawSummary))
	if err != nil {
		return nil, err
	}
	testSubject, err := jsonValue(result.Get(testapi.TestResultTestSubject))
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"testId":            jsonValueOrNull(result.GetTestID()),
		"testConfiguration": jsonValueOrNull(result.GetTestConfiguration()),
		"executionState":    result.GetExecutionState(),
		"effectiveSummary":  jsonValueOrNull(result.GetEffectiveSummary()),
		"rawSummary":        rawSummary,
		"passFail":          jsonValueOrNull(result.GetPassFail()),
		"outcomeReason":     jsonValueOrNull(result.GetOutcomeReason()),
		"errors":            jsonValueOrNull(result.GetErrors()),
		"warnings":          jsonValueOrNull(result.GetWarnings()),
		"testSubject":       testSubject,
		"findings":          findingValues,
	}, nil
}

func encodeFinding(finding testapi.FindingData) (map[string]any, error) {
	payload, err := json.Marshal(finding)
	if err != nil {
		return nil, fmt.Errorf("marshal finding: %w", err)
	}
	var encoded map[string]any
	if err := json.Unmarshal(payload, &encoded); err != nil {
		return nil, fmt.Errorf("decode finding: %w", err)
	}
	return encoded, nil
}

func jsonValueOrNull(value any) any {
	if value == nil {
		return nil
	}
	encoded, err := jsonValue(value)
	if err != nil {
		return nil
	}
	return encoded
}

func jsonValue(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if string(payload) == "null" {
		return nil, nil
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
