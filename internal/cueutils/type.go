package cueutils

import "github.com/snyk/go-application-framework/internal/restapimodels"

type LocalFinding struct {
	Findings []restapimodels.FindingResource `json:"findings"`
	Summary  restapimodels.FindingsSummary   `json:"summary"`
	Outcome  restapimodels.TestOutcome       `json:"outcome"`
}
