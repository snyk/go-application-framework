package findings

import (
	"slices"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils"
)

type FindingsFilterFunc func(local_models.FindingResource) bool

func filterSeverityASC(original []string, severityMinLevel string) []string {
	if severityMinLevel == "" {
		return original
	}

	minLevelPointer := slices.Index(original, severityMinLevel)

	if minLevelPointer >= 0 {
		return original[minLevelPointer:]
	}

	return original
}

func GetSeverityThresholdFilter(severityThreshold string, severityOrder []string) FindingsFilterFunc {
	return func(finding local_models.FindingResource) bool {
		allowed_severities := filterSeverityASC(severityOrder, severityThreshold)

		return utils.Contains(allowed_severities, string(finding.Attributes.Rating.Severity.Value))
	}
}

//// updateFindingsSummary updates the summary of the findings based on their severity levels
//func UpdateFindingsSummary(findingsModel *local_models.LocalFinding) {
//	resultMap := map[string]*json_schemas.TestSummaryResult{}
//
//	for _, finding := range findingsModel.Findings {
//		severity := string(finding.Attributes.Rating.Severity.Value)
//		if _, ok := resultMap[severity]; !ok {
//			resultMap[severity] = &json_schemas.TestSummaryResult{
//				Severity: severity,
//			}
//		}
//
//		resultMap[severity].Total++
//
//		if finding.Attributes.Suppression != nil {
//			resultMap[severity].Ignored++
//		} else {
//			resultMap[severity].Open++
//		}
//	}
//
//	results := make([]json_schemas.TestSummaryResult, 0, len(resultMap))
//	for _, v := range resultMap {
//		results = append(results, *v)
//	}
//	findingsModel.Summary.Results = results
//}

func NewFindingsCounts() local_models.TypesFindingCounts {
	return local_models.TypesFindingCounts{
		CountBy:         local_models.TypesFindingCounts_CountBy{Severity: map[string]uint32{}},
		CountByAdjusted: local_models.TypesFindingCounts_CountByAdjusted{Severity: map[string]uint32{}},
	}
}

// updateFindingsSummary updates the summary of the findings based on their severity levels
func UpdateFindingsSummary(findingsModel *local_models.LocalFinding) {
	updatedFindingCounts := NewFindingsCounts()
	updatedFindingCounts.CountKeyOrderAsc = findingsModel.Summary.Counts.CountKeyOrderAsc

	// update FindingsCount with Findings data
	for _, finding := range findingsModel.Findings {
		severity := string(finding.Attributes.Rating.Severity.Value)
		updatedFindingCounts.CountBy.Severity[severity]++

		if finding.Attributes.Suppression != nil {
			updatedFindingCounts.CountSuppressed++
		} else {
			updatedFindingCounts.CountByAdjusted.Severity[severity]++
			updatedFindingCounts.CountAdjusted++
		}
	}

	findingsModel.Summary.Counts = updatedFindingCounts
}
