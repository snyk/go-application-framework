package restapimodels

// TODO: This schema should be imported from Dragonfly
type LocalFinding struct {
	Findings []FindingResource `json:"findings"`
	Summary  FindingsSummary   `json:"summary"`
	Outcome  TestOutcome       `json:"outcome"`
}
