package subprocess_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/subprocess"
)

func sanitize(t *testing.T, env []string, dir string) []string {
	t.Helper()
	cmd := &exec.Cmd{Dir: dir, Env: env}
	require.NoError(t, subprocess.SanitizeCmdEnv(cmd))
	return cmd.Env
}

func TestSanitizeCmdEnv_FiltersEnvEntries(t *testing.T) {
	tests := []struct {
		name    string
		env     []string
		wantEnv []string
	}{
		{
			name:    "removes uppercase SNYK_ variables",
			env:     []string{"PATH=/usr/bin", "SNYK_TOKEN=secret", "HOME=/home/user"},
			wantEnv: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		{
			name:    "removes lowercase and mixed-case snyk_ variables",
			env:     []string{"snyk_token=a", "Snyk_Oauth_Token=b", "PATH=/bin"},
			wantEnv: []string{"PATH=/bin"},
		},
		{
			name:    "removes bare SNYK_ names without a value",
			env:     []string{"SNYK_", "SNYK_TOKEN", "PATH=/bin"},
			wantEnv: []string{"PATH=/bin"},
		},
		{
			name:    "removes SNYK_ entries that begin with an equals sign",
			env:     []string{"=SNYK_X=v", "=snyk_y=w", "PATH=/bin"},
			wantEnv: []string{"PATH=/bin"},
		},
		{
			name:    "removes SNYK_ variables whose value contains equals signs or is empty",
			env:     []string{"SNYK_TOKEN=a=b=c", "SNYK_EMPTY=", "PATH="},
			wantEnv: []string{"PATH="},
		},
		{
			name:    "keeps names that contain SNYK but do not start with it",
			env:     []string{"MY_SNYK_THING=1", "SNYKX=2", "SNYK=3", "XSNYK_TOKEN=4"},
			wantEnv: []string{"MY_SNYK_THING=1", "SNYKX=2", "SNYK=3", "XSNYK_TOKEN=4"},
		},
		{
			name:    "keeps Windows drive entries",
			env:     []string{"=C:=C:\\work", "SNYK_TOKEN=token"},
			wantEnv: []string{"=C:=C:\\work"},
		},
		{
			name:    "keeps an existing PWD when dir is empty",
			env:     []string{"PATH=/bin", "PWD=/stale"},
			wantEnv: []string{"PATH=/bin", "PWD=/stale"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.wantEnv, sanitize(t, tt.env, ""))
		})
	}
}

func TestSanitizeCmdEnv_SetsPWDToAbsoluteDir(t *testing.T) {
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
			name:    "removes SNYK_ variables while setting PWD",
			env:     []string{"SNYK_TOKEN=secret", "PATH=/bin"},
			dir:     "sub",
			wantEnv: []string{"PATH=/bin", "PWD=" + wantPWD},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.wantEnv, sanitize(t, tt.env, tt.dir))
		})
	}
}

func TestSanitizeCmdEnv_ReturnsErrorWhenDirCannotBeResolved(t *testing.T) {
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

	env := []string{"SNYK_TOKEN=secret", "PATH=/bin", "PWD=/stale"}
	cmd := &exec.Cmd{Dir: "sub", Env: env}

	err := subprocess.SanitizeCmdEnv(cmd)

	require.Error(t, err)
	assert.ErrorContains(t, err, "resolve working directory")
	assert.Equal(t, []string{"SNYK_TOKEN=secret", "PATH=/bin", "PWD=/stale"}, cmd.Env)
}

func TestSanitizeCmdEnv_NilCmdIsNoOp(t *testing.T) {
	assert.NoError(t, subprocess.SanitizeCmdEnv(nil))
}

func TestSanitizeCmdEnv_NilEnvStartsFromProcessEnvironment(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "process-secret")
	t.Setenv("KEEP_ME", "1")

	cmd := &exec.Cmd{}
	require.NoError(t, subprocess.SanitizeCmdEnv(cmd))

	assert.Contains(t, cmd.Env, "KEEP_ME=1")
	for _, entry := range cmd.Env {
		assert.False(t, strings.HasPrefix(strings.ToUpper(entry), "SNYK_"), "cmd.Env kept a SNYK_ variable")
	}
}

func TestSanitizeCmdEnv_DoesNotModifyCallerSlice(t *testing.T) {
	env := []string{"SNYK_TOKEN=secret", "PATH=/bin", "PWD=/stale"}
	before := append([]string(nil), env...)

	sanitize(t, env, t.TempDir())

	assert.Equal(t, before, env)
}

func TestSanitizeCmdEnv_DoesNotChangeProcessEnvironment(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "process-secret")
	before := os.Environ()

	cmd := &exec.Cmd{Dir: t.TempDir(), Env: []string{"SNYK_TOKEN=explicit", "PATH=/bin"}}
	require.NoError(t, subprocess.SanitizeCmdEnv(cmd))

	assert.Equal(t, before, os.Environ())
}

func TestSanitizeCmdEnv_ChildProcessDoesNotReceiveSnykVars(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX sh")
	}
	t.Setenv("SNYK_TOKEN", "process-secret")
	t.Setenv("KEEP_ME", "1")

	cmd := exec.Command("sh", "-c", "env")
	cmd.Dir = t.TempDir()
	require.NoError(t, subprocess.SanitizeCmdEnv(cmd))

	out, err := cmd.Output()
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	assert.Contains(t, lines, "KEEP_ME=1")
	for _, line := range lines {
		assert.False(t, strings.HasPrefix(strings.ToUpper(line), "SNYK_"), "child received a SNYK_ variable")
	}
}
