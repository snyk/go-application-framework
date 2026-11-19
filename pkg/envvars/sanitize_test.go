package envvars

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sanitize(t *testing.T, env []string, dir string, prefixes ...string) []string {
	t.Helper()
	got, err := SanitizeEnv(env, dir, prefixes...)
	require.NoError(t, err)
	return got
}

func TestSanitizeEnv_FiltersEntriesByPrefix(t *testing.T) {
	tests := []struct {
		name     string
		env      []string
		prefixes []string
		wantEnv  []string
	}{
		{
			name:     "matches prefixes case-insensitively in both directions",
			env:      []string{"snyk_token=a", "Acme_Key=b", "PATH=/bin"},
			prefixes: []string{"SNYK_", "acme_"},
			wantEnv:  []string{"PATH=/bin"},
		},
		{
			name:     "removes entries matching either of two prefixes",
			env:      []string{"SNYK_TOKEN=a", "ACME_KEY=b", "NPM_TOKEN=c", "PATH=/bin"},
			prefixes: []string{"snyk_", "acme_"},
			wantEnv:  []string{"NPM_TOKEN=c", "PATH=/bin"},
		},
		{
			name:     "removes bare names without a value",
			env:      []string{"SNYK_", "SNYK_TOKEN", "PATH=/bin"},
			prefixes: []string{"snyk_"},
			wantEnv:  []string{"PATH=/bin"},
		},
		{
			name:     "removes entries that begin with an equals sign",
			env:      []string{"=SNYK_X=v", "=snyk_y=w", "PATH=/bin"},
			prefixes: []string{"snyk_"},
			wantEnv:  []string{"PATH=/bin"},
		},
		{
			name:     "removes entries whose value contains equals signs or is empty",
			env:      []string{"SNYK_TOKEN=a=b=c", "SNYK_EMPTY=", "PATH="},
			prefixes: []string{"snyk_"},
			wantEnv:  []string{"PATH="},
		},
		{
			name:     "keeps entries where the prefix is not at the start",
			env:      []string{"MY_SNYK_THING=1", "SNYKX=2", "SNYK=3", "XSNYK_TOKEN=4"},
			prefixes: []string{"snyk_"},
			wantEnv:  []string{"MY_SNYK_THING=1", "SNYKX=2", "SNYK=3", "XSNYK_TOKEN=4"},
		},
		{
			name:     "keeps Windows drive entries",
			env:      []string{"=C:=C:\\work", "SNYK_TOKEN=token"},
			prefixes: []string{"snyk_"},
			wantEnv:  []string{"=C:=C:\\work"},
		},
		{
			name:     "an empty prefix next to a real one does not match everything",
			env:      []string{"SNYK_TOKEN=a", "NPM_TOKEN=b", "PATH=/bin"},
			prefixes: []string{"", "snyk_"},
			wantEnv:  []string{"NPM_TOKEN=b", "PATH=/bin"},
		},
		{
			name:     "only an empty prefix filters nothing",
			env:      []string{"SNYK_TOKEN=a", "NPM_TOKEN=b", "PATH=/bin"},
			prefixes: []string{""},
			wantEnv:  []string{"SNYK_TOKEN=a", "NPM_TOKEN=b", "PATH=/bin"},
		},
		{
			name:     "nil prefixes filter nothing",
			env:      []string{"SNYK_TOKEN=a", "PATH=/bin"},
			prefixes: nil,
			wantEnv:  []string{"SNYK_TOKEN=a", "PATH=/bin"},
		},
		{
			name:     "nil env gives an empty result",
			env:      nil,
			prefixes: []string{"snyk_"},
			wantEnv:  []string{},
		},
		{
			name:     "non-nil empty env stays empty",
			env:      []string{},
			prefixes: []string{"snyk_"},
			wantEnv:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantEnv, sanitize(t, tt.env, "", tt.prefixes...))
		})
	}
}

func TestSanitizeEnv_WithoutPrefixArgumentRemovesNothing(t *testing.T) {
	env := []string{"SNYK_TOKEN=a", "NPM_TOKEN=b", "PATH=/bin"}

	got, err := SanitizeEnv(env, "")

	require.NoError(t, err)
	assert.Equal(t, env, got)
}

func TestSanitizeEnv_SetsPWDToAbsoluteDir(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("PWD is not set on windows or plan9")
	}
	root := t.TempDir()
	t.Chdir(root)
	require.NoError(t, os.Mkdir("sub", 0o755))
	wantPWD, err := filepath.Abs("sub")
	require.NoError(t, err)

	tests := []struct {
		name    string
		env     []string
		dir     string
		wantEnv []string
	}{
		{
			name:    "replaces a stale PWD with the absolute dir",
			env:     []string{"PATH=/bin", "PWD=/stale"},
			dir:     "sub",
			wantEnv: []string{"PATH=/bin", "PWD=" + wantPWD},
		},
		{
			name:    "leaves a lowercase pwd entry in place",
			env:     []string{"pwd=/stale", "Pwd=/other", "PATH=/bin"},
			dir:     "sub",
			wantEnv: []string{"pwd=/stale", "Pwd=/other", "PATH=/bin", "PWD=" + wantPWD},
		},
		{
			name:    "adds PWD when none is set",
			env:     []string{"PATH=/bin"},
			dir:     "sub",
			wantEnv: []string{"PATH=/bin", "PWD=" + wantPWD},
		},
		{
			name:    "removes prefixed variables while setting PWD",
			env:     []string{"SNYK_TOKEN=secret", "PATH=/bin"},
			dir:     "sub",
			wantEnv: []string{"PATH=/bin", "PWD=" + wantPWD},
		},
		{
			name:    "empty env with a dir only gets PWD",
			env:     []string{},
			dir:     "sub",
			wantEnv: []string{"PWD=" + wantPWD},
		},
		{
			name:    "uses an already absolute dir as PWD",
			env:     []string{"PATH=/bin"},
			dir:     filepath.Join(root, "sub"),
			wantEnv: []string{"PATH=/bin", "PWD=" + wantPWD},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantEnv, sanitize(t, tt.env, tt.dir, "snyk_"))
		})
	}
}

func TestSanitizeEnv_DoesNotSetPWDOnWindowsOrPlan9(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
		t.Skip("covers the platforms where the PWD tests above are skipped")
	}

	got := sanitize(t, []string{"PATH=/bin", "PWD=/stale", "SNYK_TOKEN=secret"}, t.TempDir(), "snyk_")

	assert.Equal(t, []string{"PATH=/bin", "PWD=/stale"}, got)
}

func TestSanitizeEnv_ReturnsErrorWhenDirCannotBeResolved(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("PWD is not set on windows or plan9")
	}
	gone := filepath.Join(t.TempDir(), "gone")
	require.NoError(t, os.Mkdir(gone, 0o755))
	t.Chdir(gone)
	require.NoError(t, os.Remove(gone))
	if _, err := filepath.Abs("."); err == nil {
		t.Skip("platform resolves the working directory of a removed directory")
	}

	got, err := SanitizeEnv([]string{"SNYK_TOKEN=secret", "PATH=/bin"}, "sub", "snyk_")

	require.Error(t, err)
	assert.ErrorContains(t, err, "resolve working directory")
	assert.Nil(t, got)
}

func TestSanitizeEnv_DoesNotModifyCallerSlice(t *testing.T) {
	env := []string{"SNYK_TOKEN=secret", "PATH=/bin", "PWD=/stale"}
	before := append([]string(nil), env...)

	sanitize(t, env, t.TempDir(), "snyk_")

	assert.Equal(t, before, env)
}

func TestSanitizeEnv_ChildProcessDoesNotReceivePrefixedVars(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX sh")
	}
	t.Setenv("ACME_TOKEN", "process-secret")
	t.Setenv("KEEP_ME", "1")

	cmd := exec.Command("sh", "-c", "env")
	cmd.Dir = t.TempDir()
	env, err := SanitizeEnv(os.Environ(), cmd.Dir, "acme_")
	require.NoError(t, err)
	cmd.Env = env

	out, err := cmd.Output()
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	assert.Contains(t, lines, "KEEP_ME=1")
	for _, line := range lines {
		assert.False(t, strings.HasPrefix(strings.ToUpper(line), "ACME_"), "child received an ACME_ variable")
	}
}
