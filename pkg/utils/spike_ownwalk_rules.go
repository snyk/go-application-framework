package utils

import (
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v6/plumbing/format/gitignore"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// ownWalkRule is one ignore-file line, parsed once and tied to the folder whose rule file it came from.
type ownWalkRule struct {
	pattern gitignore.Pattern
	// nameOnly rules have no slash before an optional trailing slash, so git matches them against
	// the basename of any entry below their folder. Matching them with the full path instead would
	// also match a folder above the entry: go-git's Match reports a hit on any path component.
	nameOnly bool
	// contentsOnly rules end in "/**", which git reads as "everything inside the folder". Match
	// treats a folder candidate as standing in for its contents, so it would also match the folder
	// itself and prune it before a later negation could re-include anything inside.
	contentsOnly bool
}

func newOwnWalkRule(line string, folder []string) ownWalkRule {
	if isNameOnlyRule(line) {
		// Without a domain the rule matches any basename, which is what a name-only rule means below its folder.
		return ownWalkRule{pattern: gitignore.ParsePattern(line, nil), nameOnly: true}
	}

	return ownWalkRule{
		pattern:      gitignore.ParsePattern(line, folder),
		contentsOnly: strings.HasSuffix(strings.TrimRight(strings.TrimPrefix(line, "!"), " "), "/**"),
	}
}

func isNameOnlyRule(line string) bool {
	s := strings.TrimPrefix(line, "!")
	s = strings.TrimRight(s, " ")
	s = strings.TrimSuffix(s, "/")

	return !strings.Contains(s, "/")
}

// ownWalkRuleStack holds the rules of every folder on the current walk path. Entering a folder
// pushes its rules and leaving it truncates them, so the stack is never copied per folder.
type ownWalkRuleStack struct {
	rules []ownWalkRule
	// starts[i] is the index in rules where the rules of the i-th pushed folder begin.
	starts []int
}

func (s *ownWalkRuleStack) push(rules []ownWalkRule) {
	s.starts = append(s.starts, len(s.rules))
	s.rules = append(s.rules, rules...)
}

func (s *ownWalkRuleStack) pop() {
	last := len(s.starts) - 1
	s.rules = s.rules[:s.starts[last]]
	s.starts = s.starts[:last]
}

// excludes reports whether the deepest, last-written rule that matches decides. rel is the entry's
// path from the repository root.
func (s *ownWalkRuleStack) excludes(rel []string, isDir bool) bool {
	name := rel[len(rel)-1]

	for i := len(s.rules) - 1; i >= 0; i-- {
		rule := s.rules[i]

		path := rel
		if rule.nameOnly {
			path = []string{name}
		}
		matchAsDir := isDir && !rule.contentsOnly

		switch rule.pattern.Match(path, matchAsDir) {
		case gitignore.Exclude:
			return true
		case gitignore.Include:
			return false
		case gitignore.NoMatch:
		}
	}

	return false
}

// ownWalkParseRules reads one ignore file. Lines are gitignore syntax, which is also what .dcignore uses.
func ownWalkParseRules(content []byte, folder []string) []ownWalkRule {
	var rules []ownWalkRule

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		rules = append(rules, newOwnWalkRule(line, folder))
	}

	return rules
}

// ownWalkSnykRules returns the raw exclude paths of the requested .snyk sections as rules of the
// folder that holds the .snyk file. Expired and absolute entries are skipped, as today's parser does.
func ownWalkSnykRules(content []byte, folder []string, sections []DotSnykExcludeSectionName, logger *zerolog.Logger) []ownWalkRule {
	var file DotSnykRule
	if err := yaml.Unmarshal(content, &file); err != nil {
		logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	var rules []ownWalkRule
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

			rules = append(rules, newOwnWalkRule(entry.Path, folder))
		}
	}

	return rules
}
