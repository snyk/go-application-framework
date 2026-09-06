package toon

import (
	"fmt"
	"strconv"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

type sectionProjector struct {
	findingType testapi.FindingType
	name        string
	project     func([]testapi.TestResult) (Section, error)
}

// sectionProjectors defines supported concise TOON sections in render order.
// New products add an entry here; the template stays generic.
var sectionProjectors = []sectionProjector{
	{
		findingType: testapi.FindingTypeSca,
		name:        "sca",
		project:     projectSCASection,
	},
	{
		findingType: testapi.FindingTypeSecrets,
		name:        "secrets",
		project:     projectSecretsSection,
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
			return nil, fmt.Errorf("project %s section: %w", entry.name, err)
		}
		sections = append(sections, section)
	}
	return sections, nil
}

func projectSCASection(results []testapi.TestResult) (Section, error) {
	view, err := ProjectSCA(results)
	if err != nil {
		return Section{}, err
	}

	rows := make([][]string, 0, len(view.Rows))
	for _, row := range view.Rows {
		rows = append(rows, []string{row.ID, row.Severity, row.Pkg, row.Fixable})
	}

	return Section{
		Name: "sca",
		Columns: []Column{
			{Name: "id", Quoted: true},
			{Name: "severity", Quoted: true},
			{Name: "pkg", Quoted: true},
			{Name: "fixable", Quoted: true},
		},
		Rows:    rows,
		Summary: view.Summary,
	}, nil
}

func projectSecretsSection(results []testapi.TestResult) (Section, error) {
	view, err := ProjectSecrets(results)
	if err != nil {
		return Section{}, err
	}

	rows := make([][]string, 0, len(view.Rows))
	for _, row := range view.Rows {
		rows = append(rows, []string{row.Rule, row.Severity, row.File, strconv.Itoa(row.Line)})
	}

	return Section{
		Name: "secrets",
		Columns: []Column{
			{Name: "rule", Quoted: true},
			{Name: "severity", Quoted: true},
			{Name: "file", Quoted: true},
			{Name: "line", Quoted: false},
		},
		Rows:    rows,
		Summary: view.Summary,
	}, nil
}

func containsFindingType(types []testapi.FindingType, want testapi.FindingType) bool {
	for _, findingType := range types {
		if findingType == want {
			return true
		}
	}
	return false
}
