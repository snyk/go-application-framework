package cueutils

import "github.com/snyk/go-application-framework/internal/restapimodels"

type LocalFinding struct {
	Findings []restapimodels.FindingAttributes
	Summary  restapimodels.FindingsSummary
	Outcome  restapimodels.TestOutcome
}
