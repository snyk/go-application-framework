package utils

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// errWindowsPrivilegeNotHeld is ERROR_PRIVILEGE_NOT_HELD (1314), which os.Symlink returns on Windows
// without the symlink privilege. No POSIX errno has this value.
const errWindowsPrivilegeNotHeld = syscall.Errno(1314)

// currentImplementationName is the only implementation allowed to have known gaps: its
// failures on scenarios with currentCorrect == false are logged instead of failing the run.
const currentImplementationName = "current"

// scenario is a small repository on disk plus the exact files a correct file filter returns.
type scenario struct {
	// name is the scenario name from the correctness scenario list.
	name string
	// files maps repo-relative slash paths to content.
	files map[string]string
	// links maps a symlink path to its target: relative to the link's folder, or absolute.
	links map[string]string
	// tracked lists paths added to the git index with `git add -f` before scanning.
	tracked []string
	// scanSubdir is the scan root relative to the repo root; "" means the repo root.
	scanSubdir string
	// want lists the expected files: sorted slash paths relative to the scan root, no ".git/" entries.
	want []string
	// currentCorrect is false for a known gap of today's implementation.
	currentCorrect bool
	// gitOracle means want must equal what git itself lists, see TestScenarioWantsMatchGit.
	gitOracle bool
	// gitEnv is extra environment for git calls, e.g. GIT_CONFIG_GLOBAL=<file> for core.excludesFile.
	// It is also set while the implementation runs, so implementations that read git
	// configuration see what git sees.
	gitEnv []string
	// parentRules means the scan must also read rule files above the scan root.
	parentRules bool
	// ignoreLinkEntries drops the paths in links from both the result and want before comparing,
	// for scenarios that are not about whether link entries are listed.
	ignoreLinkEntries bool
	// why is one line shown in failure output.
	why string
	// setup runs after `git init` and before files are written, for repositories that cannot be
	// described by files alone (submodules).
	setup func(t *testing.T, repoRoot string)
	// skipReason, if set, skips the scenario for every implementation.
	skipReason string
}

type scenarioOptions struct {
	ReadParentRuleFiles bool
}

type scenarioImplementation struct {
	name string
	// sharesCurrentGaps exempts the implementation from the known gaps of today's implementation,
	// for variants that change how the filter runs but not what it matches.
	sharesCurrentGaps bool
	// run returns the files that survive filtering, as absolute or scan-root-relative paths.
	// It takes testing.TB so the benchmark can run the same implementations.
	run func(tb testing.TB, scanRoot string, opts scenarioOptions) []string
}

var scenarioImplementations []scenarioImplementation

// registerScenarioImplementation is called from an init() in the implementation's own test
// file, so implementations never edit a shared line.
func registerScenarioImplementation(impl scenarioImplementation) {
	scenarioImplementations = append(scenarioImplementations, impl)
}

func TestScenarios(t *testing.T) {
	only := os.Getenv("SCENARIO_ONLY")
	scenarios := buildScenarios(t)
	if only != "" && !slices.ContainsFunc(scenarios, func(sc scenario) bool { return sc.name == only }) {
		t.Fatalf("SCENARIO_ONLY=%q matches no scenario", only)
	}

	for _, impl := range scenarioImplementations {
		t.Run(impl.name, func(t *testing.T) {
			for _, sc := range scenarios {
				if only != "" && sc.name != only {
					continue
				}
				t.Run(sc.name, func(t *testing.T) {
					checkScenario(t, impl, sc, handWrittenWant)
				})
			}
		})
	}
}

// TestScenarioWantsMatchGit keeps the hand-written want lists honest: git wins on any disagreement.
func TestScenarioWantsMatchGit(t *testing.T) {
	for _, sc := range buildScenarios(t) {
		if !sc.gitOracle {
			continue
		}
		t.Run(sc.name, func(t *testing.T) {
			if sc.skipReason != "" {
				t.Skip(sc.skipReason)
			}

			scanRoot := buildScenarioRepo(t, sc)

			assertSamePaths(t, sc, "git", gitWant(t, sc, scanRoot), handWrittenWant(t, sc, scanRoot))
		})
	}
}

// ruleParsingCase is a rule-file parsing row. Git is the expected value.
type ruleParsingCase struct {
	scenario
	// alsoWithMetacharacterFix runs the current implementation a second time with
	// FF_FILE_FILTER_METACHARACTER_FIX on, where it must be correct.
	alsoWithMetacharacterFix bool
}

func TestRuleParsing(t *testing.T) {
	for _, impl := range scenarioImplementations {
		t.Run(impl.name, func(t *testing.T) {
			for _, row := range ruleParsingCases() {
				t.Run(row.name, func(t *testing.T) {
					checkScenario(t, impl, row.scenario, gitWant)
				})

				if row.alsoWithMetacharacterFix && impl.name == currentImplementationName {
					t.Run(row.name+" with metacharacter fix", func(t *testing.T) {
						checkScenario(t, currentWithMetacharacterFix, row.scenario, gitWant)
					})
				}
			}
		})
	}
}

func ruleParsingCases() []ruleParsingCase {
	specialCharacterRules := ruleLines(`app\[1\]/`, "a+b/", "(p)/", "{q}/", "c$d/")

	return []ruleParsingCase{
		{scenario: scenario{
			name:           "Wildcard matches a folder",
			why:            "*.o ignores a folder named a.o and its contents",
			files:          repoFiles(map[string]string{".gitignore": ruleLines("*.o")}, "a.o/x.txt", "b.o", "c.txt"),
			currentCorrect: true,
			gitOracle:      true,
		}},
		{scenario: scenario{
			name:           "Trailing spaces dropped and # comments",
			why:            "trailing spaces are dropped and a line starting with # is a comment",
			files:          repoFiles(map[string]string{".gitignore": "ignoreme  \n#ignoreme2"}, "ignoreme", "ignoreme2", "#ignoreme2"),
			currentCorrect: true,
			gitOracle:      true,
		}},
		{scenario: scenario{
			name:           "Escapes of hash, bang and space",
			why:            `\#, \! and an escaped trailing space match literal names`,
			files:          repoFiles(map[string]string{".gitignore": ruleLines(`\#hash`, `\!bang`, `trail\ `)}, "#hash", "!bang", "trail ", "plain"),
			currentCorrect: true,
			gitOracle:      true,
		}},
		{scenario: scenario{
			name:           "CRLF line endings",
			why:            "a rule file saved with CRLF line endings parses like one with LF",
			files:          repoFiles(map[string]string{".gitignore": "a.txt\r\nb/\r\n"}, "a.txt", "b/x", "c.txt"),
			currentCorrect: true,
			gitOracle:      true,
		}},
		{
			scenario: scenario{
				name: "Special characters in folder names",
				why:  "rules naming folders with regex metacharacters must still match them",
				files: repoFiles(map[string]string{".gitignore": specialCharacterRules},
					"app[1]/x.js", "a+b/y.js", "(p)/z.js", "{q}/w.js", "c$d/v.js", "ok.js"),
				gitOracle: true,
			},
			alsoWithMetacharacterFix: true,
		},
		{scenario: scenario{
			name: "Anchoring of rules with an inner slash",
			why:  "a rule with a slash inside matches relative to its rule file's folder only",
			files: repoFiles(map[string]string{".gitignore": ruleLines("doc/frotz", "a/**/b.txt")},
				"doc/frotz", "a/doc/frotz", "a/b.txt", "a/x/b.txt", "a/x/y/b.txt", "c/a/b.txt"),
			gitOracle: true,
		}},
	}
}

// buildScenarios takes t so scenarios that need folders outside the repo can create them with
// cleanup.
func buildScenarios(t *testing.T) []scenario {
	t.Helper()

	scenarios := []scenario{
		// Section 1: handled correctly by today's implementation.
		{
			name: "nested-scope-sibling",
			files: repoFiles(map[string]string{"dirA/.gitignore": ruleLines("*.something")},
				"dirA/a.something", "dirB/b.something", "c.something"),
			want:           []string{"c.something", "dirA/.gitignore", "dirB/b.something"},
			currentCorrect: true,
			gitOracle:      true,
			why:            "a rule file applies to its own folder and below, never to siblings",
		},
		{
			name: "child-negation-overrides-parent",
			files: repoFiles(map[string]string{".gitignore": ruleLines("*.log"), "dirA/.gitignore": ruleLines("!keep.log")},
				"dirA/keep.log", "dirA/other.log", "root.log", "dirB/keep.log"),
			want:           []string{".gitignore", "dirA/.gitignore", "dirA/keep.log"},
			currentCorrect: true,
			gitOracle:      true,
			why:            "a deeper negation re-includes what a parent rule ignored, only below the deeper rule file",
		},
		{
			name:           "last-line-wins",
			files:          repoFiles(map[string]string{".gitignore": ruleLines("!a.txt", "*.txt")}, "a.txt", "b.txt"),
			want:           []string{".gitignore"},
			currentCorrect: true,
			gitOracle:      true,
			why:            "within one rule file the later line overrides the earlier one",
		},
		{
			name: "anchored-vs-floating",
			files: repoFiles(map[string]string{".gitignore": ruleLines("/foo", "bar")},
				"foo", "dirA/foo", "bar", "dirA/bar", "dirA/sub/bar"),
			want:           []string{".gitignore", "dirA/foo"},
			currentCorrect: true,
			gitOracle:      true,
			why:            "a leading slash anchors to the rule file's folder, a bare name matches at any depth",
		},
		{
			name:           "contents-glob-then-reinclude",
			files:          repoFiles(map[string]string{".gitignore": ruleLines("X/**", "!X/keep")}, "X/keep", "X/other"),
			want:           []string{".gitignore", "X/keep"},
			currentCorrect: true,
			gitOracle:      true,
			why:            "X/** ignores the contents of X but not X itself, so the later negation works",
		},
		symlinkNeverFollowedScenario("no-rule", "",
			[]string{"real-dir/some-file.txt"}),
		symlinkNeverFollowedScenario("rule-on-real-file", ruleLines("real-dir/some-file.txt"),
			[]string{".gitignore"}),
		symlinkNeverFollowedScenario("rule-through-symlink-path", ruleLines("symlink-to-real-dir/some-file.txt"),
			[]string{".gitignore", "real-dir/some-file.txt"}),
		symlinkNeverFollowedScenario("rule-on-symlink-name", ruleLines("symlink-to-real-dir"),
			[]string{".gitignore", "real-dir/some-file.txt"}),
		symlinkNeverFollowedScenario("ignore-real-negate-through-symlink",
			ruleLines("real-dir/some-file.txt", "!symlink-to-real-dir/some-file.txt"),
			[]string{".gitignore"}),
		{
			name:           "tracked-file-in-ignored-dir",
			files:          repoFiles(map[string]string{".gitignore": ruleLines("vendor/")}, "vendor/lib.go", "vendor/untracked.go", "main.go"),
			tracked:        []string{"vendor/lib.go"},
			want:           []string{".gitignore", "main.go", "vendor/lib.go"},
			currentCorrect: true,
			gitOracle:      true,
			why:            "a tracked file is kept even inside an ignored folder, its untracked sibling is not",
		},
		{
			name: "snyk-dcignore-exclude-tracked-file",
			files: repoFiles(map[string]string{
				".dcignore": ruleLines("secrets/"),
				".snyk":     "exclude:\n  global:\n    - private/\n",
			}, "secrets/key.pem", "private/token.txt", "src/main.go"),
			tracked:        []string{"secrets/key.pem", "private/token.txt", "src/main.go"},
			want:           []string{".dcignore", ".snyk", "src/main.go"},
			currentCorrect: true,
			why:            ".dcignore and .snyk exclusions also apply to tracked files",
		},
		{
			name: "nested-snyk-dcignore-scope",
			files: repoFiles(map[string]string{
				"dirA/.dcignore": ruleLines("*.tmp"),
				"dirC/.snyk":     "exclude:\n  global:\n    - gen/\n",
			}, "dirA/a.tmp", "dirA/a.txt", "dirB/b.tmp", "dirC/gen/g.txt", "dirC/keep.txt", "dirD/gen/g.txt"),
			want:           []string{"dirA/.dcignore", "dirA/a.txt", "dirB/b.tmp", "dirC/.snyk", "dirC/keep.txt", "dirD/gen/g.txt"},
			currentCorrect: true,
			why:            "a .dcignore or .snyk applies to its own folder only",
		},
		{
			name: "snyk-dcignore-in-ignored-dir-excludes-tracked",
			files: repoFiles(map[string]string{".gitignore": ruleLines("vendor/"), "vendor/.dcignore": ruleLines("*.log")},
				"vendor/other.log", "vendor/keep.txt", "vendor/untracked.txt"),
			tracked:        []string{"vendor/other.log", "vendor/keep.txt"},
			want:           []string{".gitignore", "vendor/keep.txt"},
			currentCorrect: true,
			why:            "a .dcignore inside a git-ignored folder still excludes the tracked files there",
		},
		{
			name:           "submodule-is-plain-folder",
			setup:          addSubmodule,
			files:          repoFiles(nil, "libs/x/extra-untracked.txt", "top.txt"),
			want:           []string{".gitmodules", "libs/x/extra-untracked.txt", "libs/x/inner.txt", "top.txt"},
			currentCorrect: true,
			why:            "a submodule is walked like any folder; git itself would list only libs/x",
		},
		{
			name: "negation-within-dcignore-and-snyk",
			files: repoFiles(map[string]string{
				"dcignore/.dcignore":   ruleLines("*.tmp", "!keep.tmp"),
				"snyk/.snyk":           "exclude:\n  global:\n    - \"*.tmp\"\n    - \"!keep.tmp\"\n",
				"nested/.dcignore":     ruleLines("*.log"),
				"nested/sub/.dcignore": ruleLines("!keep.log"),
			}, "dcignore/keep.tmp", "dcignore/drop.tmp", "snyk/keep.tmp", "snyk/drop.tmp", "nested/top.log", "nested/sub/keep.log", "nested/sub/other.log"),
			want: []string{"dcignore/.dcignore", "dcignore/keep.tmp", "nested/.dcignore", "nested/sub/.dcignore", "nested/sub/keep.log", "snyk/.snyk", "snyk/keep.tmp"},
			// Hand-written: git has no .dcignore or .snyk, so there is no git oracle for these rules.
			currentCorrect: true,
			why:            "a ! rule re-includes what an earlier rule in the same .dcignore or .snyk excluded, and a deeper .dcignore overrides a shallower one",
		},
		{
			name: "rule-file-kinds-override-by-order",
			files: repoFiles(map[string]string{
				".dcignore":     ruleLines("*.pem"),
				".gitignore":    ruleLines("*.log", "!important.pem"),
				"sub/.dcignore": ruleLines("!keep.log"),
				"vault/.snyk":   "exclude:\n  global:\n    - \"*.pem\"\n",
			}, "important.pem", "other.pem", "root.log", "sub/keep.log", "sub/other.log", "vault/important.pem", "tracked.pem"),
			tracked:        []string{"tracked.pem"},
			want:           []string{".dcignore", ".gitignore", "important.pem", "sub/.dcignore", "sub/keep.log", "vault/.snyk"},
			currentCorrect: true,
			why:            "for untracked files the rule found last wins, and .dcignore and .snyk always drop tracked files",
		},

		// Section 2: known gaps of today's implementation.
		symlinkEntriesSkippedScenario(t),
		{
			name:      "dir-only-rule-file-named-like-rule",
			files:     repoFiles(map[string]string{".gitignore": ruleLines("foo/")}, "foo", "sub/foo/x", "other/foo"),
			want:      []string{".gitignore", "foo", "other/foo"},
			gitOracle: true,
			why:       "a rule ending in a slash matches folders only, never a file of that name",
		},
		{
			name: "dir-only-rule-allowlist",
			files: repoFiles(map[string]string{".gitignore": ruleLines("*", "!*/", "!keep.txt")},
				"keep.txt", "sub/keep.txt", "sub/other.txt", "other.txt"),
			want:      []string{"keep.txt", "sub/keep.txt"},
			gitOracle: true,
			why:       "!*/ re-includes folders only, so only keep.txt files are sent",
		},
		{
			name:      "never-include-git-dir",
			files:     repoFiles(map[string]string{".gitignore": ruleLines("*", "!*/", "!keep.txt")}, "keep.txt", "other.txt"),
			want:      []string{"keep.txt"},
			gitOracle: true,
			why:       "nothing under .git/ is returned, whatever the other rules say",
		},
		{
			name: "reinclude-in-excluded-dir-gitignore",
			files: repoFiles(map[string]string{".gitignore": ruleLines("node_modules/", "!*.config.js", "!README.md")},
				"node_modules/pkg/webpack.config.js", "node_modules/pkg/README.md", "node_modules/pkg/index.js", "webpack.config.js", "src/a.js"),
			want:      []string{".gitignore", "src/a.js", "webpack.config.js"},
			gitOracle: true,
			why:       "a file cannot be re-included once its parent folder is excluded",
		},
		{
			name: "reinclude-in-excluded-dir-dcignore",
			files: repoFiles(map[string]string{".gitignore": ruleLines("vendor/"), "vendor/.dcignore": ruleLines("!new.txt")},
				"vendor/new.txt", "main.go"),
			want: []string{".gitignore", "main.go"},
			why:  "a .dcignore negation inside an excluded folder cannot re-include a file there",
		},
		{
			name:  "unreadable-entry-is-not-silent",
			setup: unreadableFolder,
			files: repoFiles(map[string]string{"zz/.gitignore": ruleLines("*.log")}, "a.txt", "zz/keep.txt", "zz/skip.log"),
			want:  []string{"a.txt", "zz/.gitignore", "zz/keep.txt"},
			why:   "a folder the walk cannot read must not silently drop the files after it",
		},
		{
			name: "parent-gitignore-above-scan-root",
			files: repoFiles(map[string]string{".gitignore": ruleLines("node_modules/", "*.log")},
				"packages/a/node_modules/dep.js", "packages/a/a.log", "packages/a/src/b.go"),
			scanSubdir:  "packages/a",
			want:        []string{"src/b.go"},
			parentRules: true,
			gitOracle:   true,
			why:         "rule files above the scan root still apply",
		},
		{
			name:       "case-insensitive-matching",
			skipReason: "depends on the file system: git matches rule case only where core.ignorecase is set (macOS and Windows defaults), so there is no single expected list",
		},
		{
			name:      "git-info-exclude-file",
			files:     repoFiles(map[string]string{".git/info/exclude": ruleLines("secret.txt")}, "secret.txt", "ok.txt"),
			want:      []string{"ok.txt"},
			gitOracle: true,
			why:       ".git/info/exclude patterns apply",
		},
		globalExcludesFileScenario(t),
		{
			name: "scan-root-path-with-metacharacters",
			files: repoFiles(map[string]string{"a+b(c)/.gitignore": ruleLines("*.log")},
				"a+b(c)/x.log", "a+b(c)/keep.txt"),
			scanSubdir: "a+b(c)",
			want:       []string{".gitignore", "keep.txt"},
			gitOracle:  true,
			why:        "a scan folder whose absolute path contains + ( ) must not void its rules",
		},
	}

	return scenarios
}

func symlinkNeverFollowedScenario(variant string, gitignore string, want []string) scenario {
	rules := map[string]string{}
	if gitignore != "" {
		rules[".gitignore"] = gitignore
	}

	return scenario{
		name:              "symlinks-never-followed-" + variant,
		files:             repoFiles(rules, "real-dir/some-file.txt"),
		links:             map[string]string{"symlink-to-real-dir": "real-dir"},
		want:              want,
		currentCorrect:    true,
		gitOracle:         true,
		ignoreLinkEntries: true,
		why:               "a rule written through a symlink path matches nothing and the walk never enters the link",
	}
}

func symlinkEntriesSkippedScenario(t *testing.T) scenario {
	t.Helper()

	outside := newScenarioTempDir(t, "scenario-outside")
	writeScenarioFile(t, filepath.Join(outside, "vuln.js"), "x")

	return scenario{
		name:  "symlink-entries-skipped",
		files: repoFiles(nil, "real.js", "real-dir/file.js"),
		links: map[string]string{
			"linked_vuln.js": filepath.Join(outside, "vuln.js"),
			"inside-link.js": "real.js",
			"linked-dir":     "real-dir",
		},
		want: []string{"real-dir/file.js", "real.js"},
		why:  "symlink entries are never listed: reading one would upload a file from outside the repo",
	}
}

func globalExcludesFileScenario(t *testing.T) scenario {
	t.Helper()

	dir := newScenarioTempDir(t, "scenario-global")
	excludes := filepath.Join(dir, "global_ignore")
	config := filepath.Join(dir, "gitconfig")
	writeScenarioFile(t, excludes, ".DS_Store\n")
	// Git reads backslashes in config values as escapes, so a Windows path needs forward slashes.
	writeScenarioFile(t, config, "[core]\n\texcludesFile = "+filepath.ToSlash(excludes)+"\n")

	return scenario{
		name:      "global-excludes-file",
		files:     repoFiles(nil, ".DS_Store", "ok.txt"),
		gitEnv:    []string{"GIT_CONFIG_GLOBAL=" + config},
		want:      []string{"ok.txt"},
		gitOracle: true,
		why:       "core.excludesFile patterns apply",
	}
}

func addSubmodule(t *testing.T, repoRoot string) {
	t.Helper()

	inner := newScenarioTempDir(t, "scenario-inner")
	runScenarioGit(t, inner, nil, "init", "-q")
	writeScenarioFile(t, filepath.Join(inner, "inner.txt"), "x")
	runScenarioGit(t, inner, nil, "add", "inner.txt")
	runScenarioGit(t, inner, nil, "-c", "user.name=x", "-c", "user.email=x@example.com", "commit", "-q", "-m", "inner")
	// protocol.file.allow: git refuses local-path submodule clones by default.
	runScenarioGit(t, repoRoot, nil, "-c", "protocol.file.allow=always", "submodule", "add", "-q", inner, "libs/x")
}

// unreadableFolder makes a folder the walk cannot read. It sorts before zz/, so a walk that
// stops at the error misses the files in zz/.
func unreadableFolder(t *testing.T, repoRoot string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("chmod cannot make a folder unreadable on Windows")
	}

	locked := filepath.Join(repoRoot, "locked")
	writeScenarioFile(t, filepath.Join(locked, "hidden.txt"), "x")
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() {
		if err := os.Chmod(locked, 0o755); err != nil {
			t.Errorf("restoring the mode of %s: %v", locked, err)
		}
	})

	// Root ignores mode bits, so the folder stays readable and the walk cannot fail.
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("the folder stays readable after chmod 000, so permissions are not enforced here (running as root?)")
	}
}

// repoFiles builds a files map from rule files with content plus plain files with filler content.
func repoFiles(contentFiles map[string]string, plainPaths ...string) map[string]string {
	files := make(map[string]string, len(contentFiles)+len(plainPaths))
	maps.Copy(files, contentFiles)
	for _, p := range plainPaths {
		files[p] = "x"
	}
	return files
}

func ruleLines(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

type wantFunc func(tb testing.TB, sc scenario, scanRoot string) []string

func handWrittenWant(tb testing.TB, sc scenario, scanRoot string) []string {
	tb.Helper()

	want := slices.Clone(sc.want)
	slices.Sort(want)

	return dropLinkEntriesIfRequested(sc, want)
}

func gitWant(tb testing.TB, sc scenario, scanRoot string) []string {
	tb.Helper()

	output := runScenarioGit(tb, scanRoot, sc.gitEnv, "ls-files", "-z", "--cached", "--others", "--exclude-standard")

	var listed []string
	for _, p := range strings.Split(output, "\x00") {
		if p != "" {
			listed = append(listed, p)
		}
	}
	slices.Sort(listed)

	return dropLinkEntriesIfRequested(sc, slices.Compact(listed))
}

// checkScenario builds the scenario repo, runs the implementation and compares the result.
func checkScenario(t *testing.T, impl scenarioImplementation, sc scenario, expected wantFunc) {
	t.Helper()

	if sc.skipReason != "" {
		t.Skip(sc.skipReason)
	}

	scanRoot := buildScenarioRepo(t, sc)
	want := expected(t, sc, scanRoot)

	for _, entry := range scenarioGitEnv(sc.gitEnv) {
		key, value, _ := strings.Cut(entry, "=")
		t.Setenv(key, value)
	}
	got := impl.run(t, scanRoot, scenarioOptions{ReadParentRuleFiles: sc.parentRules})
	got = dropLinkEntriesIfRequested(sc, normalizeScenarioResult(t, scanRoot, got))

	knownGap := (impl.name == currentImplementationName || impl.sharesCurrentGaps) && !sc.currentCorrect
	missing, unexpected := diffPaths(want, got)
	switch {
	case len(missing) == 0 && len(unexpected) == 0 && knownGap:
		t.Logf("UNEXPECTED PASS %s/%s: marked as a known gap but the result is correct", impl.name, sc.name)
	case len(missing) == 0 && len(unexpected) == 0:
	case knownGap:
		t.Logf("KNOWN GAP %s/%s: %s", impl.name, sc.name, formatPathDiff(sc, missing, unexpected))
	default:
		t.Error(formatPathDiff(sc, missing, unexpected))
	}
}

func assertSamePaths(t *testing.T, sc scenario, expectedLabel string, expected, actual []string) {
	t.Helper()

	missing, unexpected := diffPaths(expected, actual)
	if len(missing) != 0 || len(unexpected) != 0 {
		t.Errorf("want list differs from %s; %s", expectedLabel, formatPathDiff(sc, missing, unexpected))
	}
}

// buildScenarioRepo creates the scenario on disk and returns the scan root.
func buildScenarioRepo(t *testing.T, sc scenario) string {
	t.Helper()

	// Not t.TempDir(): its path embeds the subtest name, and + ( ) in an absolute path void
	// today's unescaped glob translation, which would silently disable the scenario's rules.
	repoRoot := newScenarioTempDir(t, "scenario")

	runScenarioGit(t, repoRoot, sc.gitEnv, "init", "-q")
	if sc.setup != nil {
		sc.setup(t, repoRoot)
	}

	for relPath, content := range sc.files {
		writeScenarioFile(t, filepath.Join(repoRoot, filepath.FromSlash(relPath)), content)
	}
	for linkPath, target := range sc.links {
		fullPath := filepath.Join(repoRoot, filepath.FromSlash(linkPath))
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
		if err := os.Symlink(target, fullPath); err != nil {
			if errors.Is(err, errWindowsPrivilegeNotHeld) {
				t.Skip("creating symlinks on Windows needs Developer Mode or administrator rights")
			}
			require.NoError(t, err)
		}
	}
	if len(sc.tracked) > 0 {
		runScenarioGit(t, repoRoot, sc.gitEnv, append([]string{"add", "-f", "--"}, sc.tracked...)...)
	}

	return filepath.Join(repoRoot, filepath.FromSlash(sc.scanSubdir))
}

func newScenarioTempDir(tb testing.TB, prefix string) string {
	tb.Helper()

	dir, err := os.MkdirTemp("", prefix)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	return dir
}

func writeScenarioFile(tb testing.TB, fullPath, content string) {
	tb.Helper()

	require.NoError(tb, os.MkdirAll(filepath.Dir(fullPath), 0o755))
	require.NoError(tb, os.WriteFile(fullPath, []byte(content), 0o644))
}

// scenarioGitEnv isolates git from the machine's configuration; gitEnv entries win because the
// last value of a repeated variable is the one the child process sees.
func scenarioGitEnv(gitEnv []string) []string {
	return append([]string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}, gitEnv...)
}

func runScenarioGit(tb testing.TB, dir string, gitEnv []string, args ...string) string {
	tb.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), scenarioGitEnv(gitEnv)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(tb, cmd.Run(), "git %v\n%s", args, stderr.String())

	return stdout.String()
}

// normalizeScenarioResult turns an implementation's paths into sorted slash paths relative to
// the scan root. Duplicates are kept: returning a file twice is a bug worth seeing.
func normalizeScenarioResult(tb testing.TB, scanRoot string, paths []string) []string {
	tb.Helper()

	// A scan root under a symlinked temp folder (macOS /var) may come back resolved.
	resolvedRoot, err := filepath.EvalSymlinks(scanRoot)
	require.NoError(tb, err)

	normalized := make([]string, 0, len(paths))
	for _, p := range paths {
		if filepath.IsAbs(p) {
			rel, err := filepath.Rel(scanRoot, p)
			require.NoError(tb, err)
			if strings.HasPrefix(rel, "..") {
				rel, err = filepath.Rel(resolvedRoot, p)
				require.NoError(tb, err)
			}
			p = rel
		}
		normalized = append(normalized, filepath.ToSlash(p))
	}
	slices.Sort(normalized)

	return normalized
}

func dropLinkEntriesIfRequested(sc scenario, paths []string) []string {
	if !sc.ignoreLinkEntries {
		return paths
	}

	linkPaths := map[string]bool{}
	for linkPath := range sc.links {
		relToScanRoot := linkPath
		if sc.scanSubdir != "" {
			var underScanRoot bool
			relToScanRoot, underScanRoot = strings.CutPrefix(linkPath, sc.scanSubdir+"/")
			if !underScanRoot {
				continue
			}
		}
		linkPaths[relToScanRoot] = true
	}

	return slices.DeleteFunc(slices.Clone(paths), func(p string) bool { return linkPaths[p] })
}

// diffPaths compares as multisets, so a duplicated result is reported as unexpected.
func diffPaths(want, got []string) (missing, unexpected []string) {
	remaining := map[string]int{}
	for _, p := range want {
		remaining[p]++
	}
	for _, p := range got {
		if remaining[p] > 0 {
			remaining[p]--
			continue
		}
		unexpected = append(unexpected, p)
	}
	for _, p := range want {
		if remaining[p] > 0 {
			remaining[p]--
			missing = append(missing, p)
		}
	}

	return missing, unexpected
}

func formatPathDiff(sc scenario, missing, unexpected []string) string {
	return sc.name + ": " + sc.why +
		"\n  missing (expected, not returned): " + strings.Join(missing, ", ") +
		"\n  unexpected (returned, not expected): " + strings.Join(unexpected, ", ")
}
