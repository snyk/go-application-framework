package presenters

import (
	"slices"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

func convertTypeToIssueName(findingType testapi.FindingType) string {
	// Map backend finding types to human-friendly issue group names
	switch findingType {
	case testapi.FindingTypeSca:
		return "Security"
	case testapi.FindingTypeLicense:
		return "License"
	case testapi.FindingTypeSast:
		return "Code"
	case testapi.FindingTypeDast:
		return "DAST"
	case testapi.FindingTypeSecrets:
		return "Secrets"
	case testapi.FindingTypeRift:
		return "Rift"
	default:
		return string(findingType)
	}
}

func determineProductNameFromFindingTypes(findingTypes []testapi.FindingType) string {
	if slices.Contains(findingTypes, testapi.FindingTypeSca) || slices.Contains(findingTypes, testapi.FindingTypeLicense) {
		return "Software Composition Analysis"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeSast) {
		return "Static Code Analysis"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeSecrets) {
		return "Secret Detection"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeRift) {
		return "Rift"
	}

	if slices.Contains(findingTypes, testapi.FindingTypeDast) {
		return "Dynamic Application Security Testing"
	}

	return "Other"
}
