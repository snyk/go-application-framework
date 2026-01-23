package utils

import (
	"strings"
)

func IsSnykIde(integrationName string) bool {
	knownIdeIntegrationNames := []string{"VS_CODE", "JETBRAINS_IDE", "VISUAL_STUDIO", "ECLIPSE"}
	for _, name := range knownIdeIntegrationNames {
		if strings.EqualFold(integrationName, name) {
			return true
		}
	}
	return false
}

func IsRunningFromNpm(integrationName string) bool {
	return strings.EqualFold(integrationName, "TS_BINARY_WRAPPER")
}
