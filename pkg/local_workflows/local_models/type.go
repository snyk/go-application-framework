package local_models

import "github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"

// TODO: This schema should be imported from Dragonfly
type LocalFinding struct {
	Findings []FindingResource `json:"findings"`
	Summary  json_schemas.TestSummary
	Outcome  TestOutcome `json:"outcome"`
}
