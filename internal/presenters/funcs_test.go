package presenters

import (
	"bytes"
	htmlTemplate "html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/target"
)

func newGitRepoWithOrigin(t *testing.T, originURL string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{originURL}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("probe\n"), 0o600))
	wt, err := repo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	_, err = wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	return dir
}

func intPtr(v int) *int {
	return &v
}

func TestGetResultTargetId(t *testing.T) {
	const recorded = "pkg:git/github.com/acme/recorded@0123456789abcdef?branch=main"
	derivedRepo := func(t *testing.T) string {
		t.Helper()
		return newGitRepoWithOrigin(t, "https://github.com/acme/derived.git")
	}

	testCases := []struct {
		name     string
		metadata func(t *testing.T) map[string]interface{}
		config   func() configuration.Configuration
		want     string
		wantErr  bool
		wantRe   string
	}{
		{
			name: "recorded value wins over target directory",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetId:        recorded,
					testapi.TestResultMetadataKeyTargetDirectory: t.TempDir(),
				}
			},
			want: recorded,
		},
		{
			name: "empty recorded value falls back to deriving from target directory",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetId:        "",
					testapi.TestResultMetadataKeyTargetDirectory: derivedRepo(t),
				}
			},
			wantRe: `^pkg:git/github\.com/acme/derived@[0-9a-f]{40}\?branch=`,
		},
		{
			name: "non-string recorded value falls back to target directory",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetId:        42,
					testapi.TestResultMetadataKeyTargetDirectory: derivedRepo(t),
				}
			},
			wantRe: `^pkg:git/github\.com/acme/derived@[0-9a-f]{40}\?branch=`,
		},
		{
			name: "nil recorded value falls back to target directory",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetId:        nil,
					testapi.TestResultMetadataKeyTargetDirectory: derivedRepo(t),
				}
			},
			wantRe: `^pkg:git/github\.com/acme/derived@[0-9a-f]{40}\?branch=`,
		},
		{
			name: "neither key present gives empty id",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{}
			},
			want: "",
		},
		{
			name: "fallback honors remote repo url flag",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetDirectory: t.TempDir(),
				}
			},
			config: func() configuration.Configuration {
				config := configuration.NewInMemory()
				config.Set(target.RemoteRepoUrlFlagname, "https://github.com/acme/remote.git")
				return config
			},
			want: "pkg:git/github.com/acme/remote@unknown?branch=unknown",
		},
		{
			name: "remote repo url flag overrides a recorded filesystem id",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetId:        "pkg:filesystem/aafc908c69bc6d8cc4715275f9c19fa3be69aebc/project",
					testapi.TestResultMetadataKeyTargetDirectory: t.TempDir(),
				}
			},
			config: func() configuration.Configuration {
				config := configuration.NewInMemory()
				config.Set(target.RemoteRepoUrlFlagname, "https://github.com/acme/remote.git")
				return config
			},
			want: "pkg:git/github.com/acme/remote@unknown?branch=unknown",
		},
		{
			name: "remote repo url flag with no target directory gives empty id",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetId: "pkg:filesystem/aafc908c69bc6d8cc4715275f9c19fa3be69aebc/project",
				}
			},
			config: func() configuration.Configuration {
				config := configuration.NewInMemory()
				config.Set(target.RemoteRepoUrlFlagname, "https://github.com/acme/remote.git")
				return config
			},
			want: "",
		},
		{
			name: "derivation failure propagates its error",
			metadata: func(t *testing.T) map[string]interface{} {
				t.Helper()
				return map[string]interface{}{
					testapi.TestResultMetadataKeyTargetDirectory: derivedRepo(t),
				}
			},
			config: func() configuration.Configuration {
				config := configuration.NewInMemory()
				config.Set(target.RemoteRepoUrlFlagname, "https://[::1")
				return config
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := newTargetIdResult(t, tc.metadata(t))
			config := configuration.NewInMemory()
			if tc.config != nil {
				config = tc.config()
			}

			got, err := getResultTargetId(result, config)
			if tc.wantErr {
				require.ErrorContains(t, err, "unknown repoUrl format")
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			if tc.wantRe != "" {
				assert.Regexp(t, tc.wantRe, got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func newTargetIdResult(t *testing.T, metadata map[string]interface{}) testapi.TestResult {
	t.Helper()
	result := mocks.NewMockTestResult(gomock.NewController(t))
	result.EXPECT().GetMetadataValue(gomock.Any()).DoAndReturn(func(key string) interface{} {
		return metadata[key]
	}).AnyTimes()
	return result
}

func TestResolveMessageArgs(t *testing.T) {
	testCases := []struct {
		desc string
		text string
		args []string
		want string
	}{
		{
			desc: "normal replacement of two placeholders",
			text: "input from {0} flows into {1}",
			args: []string{"a file", "readFile"},
			want: "input from a file flows into readFile",
		},
		{
			desc: "no placeholders in text",
			text: "no placeholders here",
			args: []string{"arg0"},
			want: "no placeholders here",
		},
		{
			desc: "empty args leaves placeholders intact",
			text: "{0} is {1}",
			args: []string{},
			want: "{0} is {1}",
		},
		{
			desc: "more placeholders than args leaves extras intact",
			text: "{0} and {1} and {2}",
			args: []string{"only", "two"},
			want: "only and two and {2}",
		},
		{
			desc: "empty text returns empty string",
			text: "",
			args: []string{"arg0"},
			want: "",
		},
		{
			desc: "nil args leaves placeholders intact",
			text: "text {0}",
			args: nil,
			want: "text {0}",
		},
		{
			desc: "single placeholder single arg",
			text: "hello {0}!",
			args: []string{"world"},
			want: "hello world!",
		},
		{
			desc: "repeated placeholder is replaced in all occurrences",
			text: "{0} and {0} again",
			args: []string{"val"},
			want: "val and val again",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := resolveMessageArgs(tc.text, tc.args)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReadLineMarked(t *testing.T) {
	// Create a temp file with known content for testing.
	tmpDir := t.TempDir()
	testFileName := "test_source.go"
	testFilePath := filepath.Join(tmpDir, testFileName)
	content := "hello world\n\tfmt.Println(x)\nabcdefghij\n"
	err := os.WriteFile(testFilePath, []byte(content), 0644)
	assert.NoError(t, err)

	cache := newSourceLineCache([]string{tmpDir})

	testCases := []struct {
		desc    string
		file    string
		line    int
		fromCol *int
		toCol   *int
		want    [3]string
	}{
		{
			desc:    "normal case - mark middle of line",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   intPtr(12),
			want:    [3]string{"hello ", "world", ""},
		},
		{
			desc:    "nil fromCol returns full line as prefix",
			file:    testFileName,
			line:    1,
			fromCol: nil,
			toCol:   intPtr(5),
			want:    [3]string{"hello world", "", ""},
		},
		{
			desc:    "nil toCol marks to end of line",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   nil,
			want:    [3]string{"hello ", "world", ""},
		},
		{
			desc:    "fromCol beyond line length returns full line as prefix with empty marker",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(100),
			toCol:   intPtr(105),
			want:    [3]string{"hello world", "", ""},
		},
		{
			desc:    "toCol before fromCol results in empty marker",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   intPtr(3),
			want:    [3]string{"hello ", "", "world"},
		},
		{
			desc:    "fromCol at 1 marks from beginning",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(1),
			toCol:   intPtr(7),
			want:    [3]string{"", "hello ", "world"},
		},
		{
			desc:    "missing file returns all empty strings",
			file:    "nonexistent.go",
			line:    1,
			fromCol: intPtr(1),
			toCol:   intPtr(5),
			want:    [3]string{"", "", ""},
		},
		{
			desc:    "line out of range returns all empty strings",
			file:    testFileName,
			line:    999,
			fromCol: intPtr(1),
			toCol:   intPtr(5),
			want:    [3]string{"", "", ""},
		},
		{
			desc:    "line 0 returns all empty strings",
			file:    testFileName,
			line:    0,
			fromCol: intPtr(1),
			toCol:   intPtr(5),
			want:    [3]string{"", "", ""},
		},
		{
			desc:    "second line with tab",
			file:    testFileName,
			line:    2,
			fromCol: intPtr(2),
			toCol:   intPtr(15),
			want:    [3]string{"\t", "fmt.Println(x", ")"},
		},
		{
			desc:    "mark entire line",
			file:    testFileName,
			line:    3,
			fromCol: intPtr(1),
			toCol:   nil,
			want:    [3]string{"", "abcdefghij", ""},
		},
		{
			desc:    "both fromCol and toCol nil returns full line as prefix",
			file:    testFileName,
			line:    1,
			fromCol: nil,
			toCol:   nil,
			want:    [3]string{"hello world", "", ""},
		},
		{
			desc:    "fromCol equals toCol gives single char marker due to 1-based fromCol",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(3),
			toCol:   intPtr(3),
			want:    [3]string{"he", "l", "lo world"},
		},
		{
			desc:    "toCol beyond line length is clamped",
			file:    testFileName,
			line:    1,
			fromCol: intPtr(7),
			toCol:   intPtr(100),
			want:    [3]string{"hello ", "world", ""},
		},
		{
			desc:    "SARIF exclusive end column does not include extra character",
			file:    testFileName,
			line:    3,
			fromCol: intPtr(3),
			toCol:   intPtr(6),
			want:    [3]string{"ab", "cde", "fghij"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := cache.ReadLineMarked(tc.file, tc.line, tc.fromCol, tc.toCol)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSourceLineCacheRejectsFilesOutsideBaseDirectory(t *testing.T) {
	parentDir := t.TempDir()
	baseDir := filepath.Join(parentDir, "project")
	require.NoError(t, os.Mkdir(baseDir, 0o755))

	outsideFile := filepath.Join(parentDir, "outside.go")
	require.NoError(t, os.WriteFile(outsideFile, []byte("secret\n"), 0o600))

	cache := newSourceLineCache([]string{baseDir})
	assert.Empty(t, cache.ReadLine(filepath.Join("..", "outside.go"), 1))
	assert.Empty(t, cache.ReadLine(outsideFile, 1))
}

func TestSourceLineCacheRejectsOversizedLines(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "minified.js")
	longLine := strings.Repeat("x", 70*1024)
	require.NoError(t, os.WriteFile(testFile, []byte(longLine+"\nsecond\n"), 0o600))

	cache := newSourceLineCache([]string{tmpDir})
	assert.Empty(t, cache.ReadLine("minified.js", 1))
	assert.Empty(t, cache.ReadLine("minified.js", 2))
}

func TestIsAllowedHref(t *testing.T) {
	testCases := []struct {
		desc  string
		href  string
		allow bool
	}{
		{desc: "https URL", href: "https://example.com", allow: true},
		{desc: "http URL", href: "http://search.maven.org/#foo", allow: true},
		{desc: "npm vulnerability id", href: "npm:ws:20171108", allow: true},
		{desc: "patch vulnerability id", href: "patch:npm:hoek:20180212:1", allow: true},
		{desc: "snyk vulnerability id without scheme", href: "SNYK-JAVA-COMMONSFILEUPLOAD-30082", allow: true},
		{desc: "fragment only", href: "#section", allow: true},
		{desc: "mailto URL", href: "mailto:user@example.com", allow: false},
		{desc: "relative path", href: "./docs/page.html", allow: false},
		{desc: "ftp URL", href: "ftp://example.com/file", allow: false},
		{desc: "javascript scheme", href: "javascript:alert(1)", allow: false},
		{desc: "entity-encoded javascript scheme", href: "javascript&colon;alert(1)", allow: false},
		{desc: "double entity-encoded javascript scheme", href: "javascript&amp;colon;alert(1)", allow: false},
		{desc: "numeric entity javascript scheme", href: "javascript&#58;alert(1)", allow: false},
		{desc: "data scheme", href: "data:text/html,<script>alert(1)</script>", allow: false},
		{desc: "vbscript scheme", href: "vbscript:alert(1)", allow: false},
		{desc: "protocol-relative URL", href: "//evil.example/phish", allow: false},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.allow, isAllowedHref(tc.href))
		})
	}
}

func TestMarkdownToHTMLBlocksEncodedJavascriptLinks(t *testing.T) {
	payloads := []string{
		"[click](javascript&colon;alert(1))",
		"[click](javascript&amp;colon;alert(1))",
		"[click](javascript&#58;alert(1))",
		"[click](javascript:alert(1))",
	}

	for _, input := range payloads {
		result := string(MarkdownToHTML(input))
		assert.NotContains(t, result, `<a href="javascript`)
		assert.NotContains(t, result, `<a href="javascript&colon;`)
		assert.NotContains(t, result, `<a href="javascript&#58;`)
		assert.Contains(t, result, "click")
	}
}

func TestMarkdownToHTMLAllowsSnykToHTMLLinkShapes(t *testing.T) {
	testCases := []struct {
		input    string
		contains []string
	}{
		{
			input:    "[maven](http://search.maven.org/#foo)",
			contains: []string{`href="http://search.maven.org/#foo"`},
		},
		{
			input:    "[ws](npm:ws:20171108)",
			contains: []string{`href="npm:ws:20171108"`},
		},
		{
			input:    "[commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082)",
			contains: []string{`href="SNYK-JAVA-COMMONSFILEUPLOAD-30082"`},
		},
	}

	for _, tc := range testCases {
		result := string(MarkdownToHTML(tc.input))
		for _, expected := range tc.contains {
			assert.Contains(t, result, expected)
		}
	}
}

func TestMarkdownToHTMLInHTMLTemplateDoesNotBypassHrefSanitization(t *testing.T) {
	tmpl := htmlTemplate.Must(htmlTemplate.New("report").Funcs(htmlTemplate.FuncMap{
		"markdownToHTML": MarkdownToHTML,
	}).Parse(`<div class="issue-description">{{ markdownToHTML . }}</div>`))

	var buf bytes.Buffer
	require.NoError(t, tmpl.Execute(&buf, "[click](javascript&colon;alert(1))"))

	rendered := buf.String()
	assert.NotContains(t, rendered, `<a href="javascript`)
	assert.Contains(t, rendered, "click")
}

func TestMarkdownToHTMLDoesNotTreatCodeSpanBracketsAsLinks(t *testing.T) {
	// Regression test: a regex character class such as `[[\]()#;?]*` inside
	// an inline code span (e.g. the ansi-regex ReDoS advisory text) must not
	// be misinterpreted as markdown link syntax. Link matching used to run
	// before code spans were protected from further inline processing, so
	// the `[` ... `]` ... `(` ... `)` sequence inside the code span was
	// parsed as a `[text](href)` link with an empty href.
	input := "the sub-patterns`[[\\]()#;?]*` and `(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*`."
	result := string(MarkdownToHTML(input))

	assert.NotContains(t, result, `<a href="`)
	assert.Contains(t, result, "<code>[[\\]()#;?]*</code>")
	assert.Contains(t, result, "<code>(?:;[-a-zA-Z\\d\\/#&amp;.:=?%@~_]*)*</code>")
}

func TestMarkdownToHTMLPreservesCodeSpansInsideLinkText(t *testing.T) {
	result := string(MarkdownToHTML("[npm `ws` package](https://snyk.io/vuln/npm:ws:20171108)"))

	assert.Contains(t, result, `<a href="https://snyk.io/vuln/npm:ws:20171108" target="_blank" rel="noopener noreferrer">npm <code>ws</code> package</a>`)
}

func TestMarkdownToHTMLNormalizesLineEndings(t *testing.T) {
	rendered := string(MarkdownToHTML("line one\r\n```\nline two  \n   \n```\rline three"))

	assert.NotContains(t, rendered, "\r")
	assert.NotContains(t, rendered, "line two  \n")
	assert.NotContains(t, rendered, "\n   \n")
}

func TestDerefStr(t *testing.T) {
	value := "help"
	assert.Equal(t, "help", derefStr(&value))
	assert.Equal(t, "", derefStr(nil))
}

func TestGetFingerprints(t *testing.T) {
	fallback := map[string]string{
		"identity":              "fallback-id",
		"snyk/asset/finding/v1": "fallback-id",
	}

	t.Run("nil extra uses fallback", func(t *testing.T) {
		assert.Equal(t, fallback, getFingerprints(nil, "fallback-id"))
	})

	t.Run("empty fingerprints use fallback", func(t *testing.T) {
		extra := &ufm_helpers.FindingExtra{Fingerprints: map[string]string{}}
		assert.Equal(t, fallback, getFingerprints(extra, "fallback-id"))
	})

	t.Run("existing fingerprints are returned as is", func(t *testing.T) {
		fps := map[string]string{"identity": "abc", "0": "def"}
		extra := &ufm_helpers.FindingExtra{Fingerprints: fps}
		assert.Equal(t, fps, getFingerprints(extra, "fallback-id"))
	})
}
