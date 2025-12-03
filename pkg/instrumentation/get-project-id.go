package instrumentation

import (
	"regexp"
)

func GetProjectIdAndMonitorIdFromText(text string) ([][2]string, error) {
	// Pattern: /org/{org-slug}/project/{project-uuid}/history/{history-uuid}
	re := regexp.MustCompile(`/org/[^/]+/project/([0-9a-fA-F-]{36})/history/([0-9a-fA-F-]{36})`)
	matches := re.FindAllStringSubmatch(text, -1)

	if len(matches) == 0 {
		return nil, nil
	}

	result := make([][2]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		result = append(result, [2]string{m[1], m[2]})
	}

	return result, nil
}
