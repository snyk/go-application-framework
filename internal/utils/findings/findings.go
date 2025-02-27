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
	allowed_severities := filterSeverityASC(severityOrder, severityThreshold)
	return func(finding local_models.FindingResource) bool {
		return utils.Contains(allowed_severities, string(finding.Attributes.Rating.Severity.Value))
	}
}
