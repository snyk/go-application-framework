package cueutils

import "github.com/snyk/go-application-framework/internal/restapimodels"

// TODO: This schema should be imported from Dragonfly
type LocalFinding struct {
	Findings []restapimodels.FindingResource `json:"findings"`
	Summary  restapimodels.FindingsSummary   `json:"summary"`
	Outcome  restapimodels.TestOutcome       `json:"outcome"`
}
