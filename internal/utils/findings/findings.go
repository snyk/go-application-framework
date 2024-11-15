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

// updateFindingsSummary updates the summary of the findings based on their severity levels
func UpdateFindingsSummary(findingsModel *local_models.LocalFinding) {
	findingCounts := &findingsModel.Summary.Counts

	// update FindingsCount with Findings data
	for _, finding := range findingsModel.Findings {
		severity := string(finding.Attributes.Rating.Severity.Value)
		findingCounts.CountBy.Severity[severity]++

		if finding.Attributes.Suppression != nil {
			findingCounts.CountSuppressed++
		} else {
			findingCounts.CountByAdjusted.Severity[severity]++
			findingCounts.CountAdjusted++
		}
	}
}
