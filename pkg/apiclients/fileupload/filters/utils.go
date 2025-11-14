package filters

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func getFilterURL(baseURL string, orgID uuid.UUID, isFedRamp bool) string {
	if isFedRamp {
		return fmt.Sprintf("%s/hidden/orgs/%s/code/filters", baseURL, orgID)
	}

	deeproxyURL := strings.ReplaceAll(baseURL, "api", "deeproxy")
	return fmt.Sprintf("%s/filters", deeproxyURL)
}
