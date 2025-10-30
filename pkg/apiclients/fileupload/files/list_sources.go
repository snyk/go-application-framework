package listsources

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/utils"
)

// ForPath returns a channel that notifies each file in the path that doesn't match the filter rules.
func ForPath(path string, logger *zerolog.Logger, maxThreads int) (<-chan string, error) {
	filter := utils.NewFileFilter(path, logger, utils.WithThreadNumber(maxThreads))
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, fmt.Errorf("failed to get rules: %w", err)
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}
