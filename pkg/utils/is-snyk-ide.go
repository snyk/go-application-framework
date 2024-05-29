package utils

import (
	"strings"
)

func IsSnykIde(environmentName string) bool {
	knownIdeEnvironmentNames := []string{"VS_CODE", "JETBRAINS_IDE", "VISUAL_STUDIO", "ECLIPSE"}
	for _, name := range knownIdeEnvironmentNames {
		if strings.EqualFold(environmentName, name) {
			return true
		}
	}
	return false
}
