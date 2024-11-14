package local_models

import "github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"

type FindingResource TypesFindingResource
type TestOutcome TypesTestOutcome

// TODO: This schema should be imported from Dragonfly
type LocalFinding struct {
	Findings   []FindingResource    `json:"findings"`
	Outcome    TestOutcome          `json:"outcome"`
	Rules      []TypesRules         `json:"rules"`
	NewSummary TypesFindingsSummary `json:"newSummary"`
	Summary    json_schemas.TestSummary
}

type UnionInterface interface {
	ValueByDiscriminator() (interface{}, error)
}
