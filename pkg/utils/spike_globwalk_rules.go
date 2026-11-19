package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	gitignore "github.com/sabhiram/go-gitignore"
)

// globRules is the rule set in force for one folder. It holds the translated globs of the folder's
// own rule files and of every ancestor's, in the order today's flat list has them.
type globRules struct {
	// allGlobs are the .gitignore, .dcignore and .snyk rules. They decide untracked files and folders.
	allGlobs []string
	all      *gitignore.GitIgnore
	// snykGlobs are the .dcignore and .snyk rules. They decide tracked files, which .gitignore rules
	// never exclude.
	snykGlobs []string
	snyk      *gitignore.GitIgnore
}

// extendRules returns the rules for dir, given the rules of its parent. It returns parent itself when
// dir adds no globs, so the parent's compiled matchers are reused. A .gitignore is read only when
// readGitignore is set: a folder that git ignores has its own .gitignore files skipped, while its
// .dcignore and .snyk files still apply to the tracked files below it.
func (w *globWalk) extendRules(dir string, entries []fs.DirEntry, parent *globRules, readGitignore bool) *globRules {
	var ownAll, ownSnyk []string
	for _, entry := range entries { // name order, as filepath.WalkDir visits them
		name := entry.Name()
		if entry.IsDir() || (name != ".gitignore" && name != ".dcignore" && name != ".snyk") {
			continue
		}
		if name == ".gitignore" && !readGitignore {
			continue
		}

		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			w.fw.logger.Error().Msgf("read rule file failed: %v", err)
			continue
		}

		if name == ".snyk" {
			globs := w.fw.parseDotSnykFile(content, dir, w.enableMetacharacterFix)
			ownAll = append(ownAll, globs...)
			ownSnyk = append(ownSnyk, globs...)
			continue
		}

		globs := parseIgnoreFile(content, dir, w.enableMetacharacterFix)
		ownAll = append(ownAll, globs...)
		if name == ".dcignore" {
			ownSnyk = append(ownSnyk, globs...)
		}
	}

	if len(ownAll) == 0 {
		return parent
	}

	rules := &globRules{
		allGlobs:  slices.Concat(parent.allGlobs, ownAll),
		snykGlobs: parent.snykGlobs,
		snyk:      parent.snyk,
	}
	rules.all = w.compile(rules.allGlobs)
	if len(ownSnyk) > 0 {
		rules.snykGlobs = slices.Concat(parent.snykGlobs, ownSnyk)
		rules.snyk = w.compile(rules.snykGlobs)
	}

	return rules
}

// compile builds a matcher and counts it, so benchmarks can show how many were built.
func (w *globWalk) compile(globs []string) *gitignore.GitIgnore {
	w.matchersCompiled++
	return gitignore.CompileIgnoreLines(globs...)
}
