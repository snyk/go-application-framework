package local_models

type FindingResource TypesFindingResource
type TestOutcome TypesTestOutcome

// TODO: This schema should be imported from Dragonfly
type LocalFinding struct {
	Findings []FindingResource    `json:"findings"`
	Outcome  TestOutcome          `json:"outcome"`
	Rules    []TypesRules         `json:"rules"`
	Summary  TypesFindingsSummary `json:"summary"`
}

type UnionInterface interface {
	ValueByDiscriminator() (interface{}, error)
}
