package toon

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

type sectionProjector struct {
	findingType testapi.FindingType
	project     func([]testapi.TestResult) (Section, error)
}

// sectionProjectors defines supported concise TOON sections in render order.
// New products add an entry here; the template stays generic.
var sectionProjectors = []sectionProjector{
	{
		findingType: testapi.FindingTypeSca,
		project:     ProjectSCA,
	},
	{
		findingType: testapi.FindingTypeSecrets,
		project:     ProjectSecrets,
	},
}

// ProjectSections renders registered TOON sections for finding types present in the scan.
func ProjectSections(results []testapi.TestResult, presentTypes []testapi.FindingType) ([]Section, error) {
	sections := make([]Section, 0, len(sectionProjectors))
	for _, entry := range sectionProjectors {
		if !containsFindingType(presentTypes, entry.findingType) {
			continue
		}
		section, err := entry.project(results)
		if err != nil {
			return nil, fmt.Errorf("project %s section: %w", entry.findingType, err)
		}
		sections = append(sections, section)
	}
	return sections, nil
}

func containsFindingType(types []testapi.FindingType, want testapi.FindingType) bool {
	for _, findingType := range types {
		if findingType == want {
			return true
		}
	}
	return false
}
