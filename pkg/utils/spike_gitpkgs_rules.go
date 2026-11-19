package utils

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/gitignore"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// gitPkgsRuleStack holds one matcher per folder on the current walk path, ordered from the
// repository root down. The library can only add rules to a matcher, never remove them, so a folder's
// rules live in a matcher of their own that is dropped when the walk leaves the folder.
type gitPkgsRuleStack struct {
	// matchers may hold nil for a folder without rule files, so that push and pop always pair up.
	matchers []*gitignore.Matcher
}

func (s *gitPkgsRuleStack) push(m *gitignore.Matcher) {
	s.matchers = append(s.matchers, m)
}

func (s *gitPkgsRuleStack) pop() {
	s.matchers = s.matchers[:len(s.matchers)-1]
}

// excludes reports whether the deepest, last-written rule that matches decides. rel is the entry's
// slash path from the repository root, with a trailing slash for a folder.
func (s *gitPkgsRuleStack) excludes(rel string) bool {
	for i := len(s.matchers) - 1; i >= 0; i-- {
		if s.matchers[i] == nil {
			continue
		}

		// MatchDetail, not Match: a negated match and no match both return false from Match, and
		// only a negated match stops the search at this folder.
		if result := s.matchers[i].MatchDetail(rel); result.Matched {
			return result.Ignored
		}
	}

	return false
}

// gitPkgsMatcher returns a matcher holding the rules of the given ignore files, scoped to folder.
func gitPkgsMatcher(folder string, contents ...[]byte) *gitignore.Matcher {
	m := gitignore.New("")
	for _, content := range contents {
		m.AddPatterns(content, folder)
	}

	return m
}

// gitPkgsRulesFromFile returns a matcher for one ignore file, or nil if it does not exist.
func gitPkgsRulesFromFile(file, folder string, logger *zerolog.Logger) *gitignore.Matcher {
	content, err := os.ReadFile(file)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn().Err(err).Msgf("cannot read ignore file %s", file)
		}
		return nil
	}

	return gitPkgsMatcher(folder, content)
}

// gitPkgsSnykPaths returns the raw exclude paths of the requested .snyk sections as gitignore lines.
// Expired and absolute entries are skipped, as today's parser does.
func gitPkgsSnykPaths(content []byte, sections []DotSnykExcludeSectionName, logger *zerolog.Logger) []byte {
	var file DotSnykRule
	if err := yaml.Unmarshal(content, &file); err != nil {
		logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	var lines []string
	for _, section := range sections {
		node, ok := file.Exclude[section]
		if !ok {
			continue
		}

		var entries []dotSnykExclude
		if err := node.Decode(&entries); err != nil {
			logger.Error().Msgf("parse .snyk section %q failed: %v", section, err)
			continue
		}

		for _, entry := range entries {
			expired, err := entry.IsExpired()
			if err != nil {
				logger.Error().Msgf("parse .snyk expires: %v", err)
			}
			if expired {
				continue
			}
			if filepath.IsAbs(entry.Path) {
				logger.Warn().Msgf("Absolute paths are currently not supported when excluding files (%s)", entry.Path)
				continue
			}

			lines = append(lines, entry.Path)
		}
	}

	return []byte(strings.Join(lines, "\n"))
}
