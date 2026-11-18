package utils

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v6/plumbing/format/config"
	"github.com/go-git/go-git/v6/plumbing/format/gitignore"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

const (
	gitignoreFileName = ".gitignore"
	dcignoreFileName  = ".dcignore"
	dotSnykFileName   = ".snyk"
	dotGitName        = ".git"
)

// readRuleLines returns the rules of a gitignore-style file: comments and blank lines are dropped,
// line endings (LF or CRLF) are not part of a rule.
func readRuleLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}

	return lines, scanner.Err()
}

// parseRuleLines scopes each rule to the folder of its rule file, given as path components
// relative to the walk root, as git does.
func parseRuleLines(lines []string, folder []string) []gitignore.Pattern {
	patterns := make([]gitignore.Pattern, 0, len(lines))
	for _, line := range lines {
		patterns = append(patterns, newWalkPattern(line, folder))
	}

	return patterns
}

// walkPattern adapts a go-git pattern to a walk that has already decided every ancestor folder.
// go-git's matcher re-evaluates the whole path on each query, which differs from git where it matters:
//   - a rule without an inner slash also matches a folder name higher up in the path, so `!*/` would
//     re-include a file below any folder;
//   - a rule ending in `/**` also matches the folder it names, so a later negation inside that folder
//     (`X/**` then `!X/keep`) never gets to run.
type walkPattern struct {
	inner  gitignore.Pattern
	domain []string
	// lastComponentOnly marks rules without an inner slash: they match one path component, the last.
	lastComponentOnly bool
	// contentsOnly marks rules ending in `/**`: they match what is inside a folder, never the folder.
	contentsOnly bool
}

func newWalkPattern(line string, domain []string) gitignore.Pattern {
	rule := strings.TrimPrefix(line, "!")
	if !strings.HasSuffix(rule, "\\ ") {
		rule = strings.TrimRight(rule, " ")
	}
	rule = strings.TrimSuffix(rule, "/")

	return &walkPattern{
		inner:             gitignore.ParsePattern(line, domain),
		domain:            append([]string(nil), domain...),
		lastComponentOnly: !strings.Contains(rule, "/"),
		contentsOnly:      strings.HasSuffix(rule, "/**") && !strings.HasSuffix(line, "/"),
	}
}

func (p *walkPattern) Match(path []string, isDir bool) gitignore.MatchResult {
	if p.contentsOnly {
		isDir = false
	}
	if !p.lastComponentOnly {
		return p.inner.Match(path, isDir)
	}
	if len(path) <= len(p.domain) {
		return gitignore.NoMatch
	}
	for i, component := range p.domain {
		if path[i] != component {
			return gitignore.NoMatch
		}
	}

	probe := make([]string, len(p.domain)+1)
	copy(probe, p.domain)
	probe[len(p.domain)] = path[len(path)-1]

	return p.inner.Match(probe, isDir)
}

func readGitignorePatterns(path string, folder []string) ([]gitignore.Pattern, error) {
	lines, err := readRuleLines(path)
	if err != nil {
		return nil, err
	}

	return parseRuleLines(lines, folder), nil
}

// readSnykAndDcignorePatterns reads the rules a Snyk scan applies on top of git's: .dcignore lines
// and the exclude entries of the requested .snyk sections. Only the files named by the flags are read.
func readSnykAndDcignorePatterns(dir string, folder []string, hasDcignore, hasDotSnyk bool, sections []DotSnykExcludeSectionName, logger *zerolog.Logger) ([]gitignore.Pattern, error) {
	var patterns []gitignore.Pattern

	if hasDcignore {
		lines, err := readRuleLines(filepath.Join(dir, dcignoreFileName))
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, parseRuleLines(lines, folder)...)
	}

	if hasDotSnyk {
		content, err := os.ReadFile(filepath.Join(dir, dotSnykFileName))
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, parseRuleLines(dotSnykExcludeRules(content, sections, logger), folder)...)
	}

	return patterns, nil
}

// dotSnykExcludeRules returns the raw exclude rules of the requested sections that are not expired.
func dotSnykExcludeRules(content []byte, sections []DotSnykExcludeSectionName, logger *zerolog.Logger) []string {
	var parsed DotSnykRule
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	var rules []string
	for _, section := range sections {
		node, ok := parsed.Exclude[section]
		if !ok {
			continue
		}

		var sectionRules []dotSnykExclude
		if err := node.Decode(&sectionRules); err != nil {
			logger.Error().Msgf("parse .snyk section %q failed: %v", section, err)
			continue
		}

		for _, rule := range sectionRules {
			isExpired, err := rule.IsExpired()
			// An invalid expiry counts as not expired.
			if err != nil {
				logger.Error().Msgf("parse .snyk expires: %v", err)
			}
			if isExpired {
				continue
			}
			if filepath.IsAbs(rule.Path) {
				logger.Warn().Msgf("Absolute paths are currently not supported when excluding files (%s)", rule.Path)
				continue
			}
			rules = append(rules, rule.Path)
		}
	}

	return rules
}

// readGlobalExcludePatterns returns the patterns of git's global excludes file: core.excludesFile
// from the user's git configuration, else git's default location.
func readGlobalExcludePatterns() []gitignore.Pattern {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" && home != "" {
		configHome = filepath.Join(home, ".config")
	}

	excludesFile := ""
	for _, configPath := range globalGitConfigPaths(home, configHome) {
		if excludesFile = excludesFileFromConfig(configPath, home); excludesFile != "" {
			break
		}
	}
	if excludesFile == "" && configHome != "" {
		excludesFile = filepath.Join(configHome, "git", "ignore")
	}
	if excludesFile == "" {
		return nil
	}

	patterns, readErr := readGitignorePatterns(excludesFile, nil)
	if readErr != nil {
		return nil
	}

	return patterns
}

func globalGitConfigPaths(home, configHome string) []string {
	if override := os.Getenv("GIT_CONFIG_GLOBAL"); override != "" {
		return []string{override}
	}

	var paths []string
	if home != "" {
		paths = append(paths, filepath.Join(home, ".gitconfig"))
	}
	if configHome != "" {
		paths = append(paths, filepath.Join(configHome, "git", "config"))
	}

	return paths
}

func excludesFileFromConfig(configPath, home string) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	parsed := config.New()
	if err := config.NewDecoder(file).Decode(parsed); err != nil {
		return ""
	}

	value := parsed.Section("core").Options.Get("excludesfile")
	if rest, ok := strings.CutPrefix(value, "~/"); ok && home != "" {
		return filepath.Join(home, rest)
	}

	return value
}
