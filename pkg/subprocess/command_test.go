package subprocess_test

import (
	"context"
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

const (
	helperEnvVar   = "GAF_WANT_HELPER_PROCESS"
	envHelper      = "TestHelperProcess_PrintEnv"
	dirHelper      = "TestHelperProcess_PrintWorkingDir"
	argsHelper     = "TestHelperProcess_PrintArgs"
	staleParentPWD = "/parent/stale"
)

// Re-executed by the tests below; prints the child environment.
func TestHelperProcess_PrintEnv(t *testing.T) {
	if os.Getenv(helperEnvVar) != "1" {
		return
	}
	for _, entry := range os.Environ() {
		_, _ = os.Stdout.WriteString(entry + "\n")
	}
	os.Exit(0)
}

// Re-executed by the tests below; prints the working directory and the PWD variable.
func TestHelperProcess_PrintWorkingDir(t *testing.T) {
	if os.Getenv(helperEnvVar) != "1" {
		return
	}
	wd, err := os.Getwd()
	if err != nil {
		os.Exit(1)
	}
	_, _ = os.Stdout.WriteString(wd + "\n" + os.Getenv("PWD") + "\n")
	os.Exit(0)
}

// Re-executed by the tests below; prints each argument that follows "--".
func TestHelperProcess_PrintArgs(t *testing.T) {
	if os.Getenv(helperEnvVar) != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg != "--" {
			continue
		}
		for _, value := range os.Args[i+1:] {
			_, _ = os.Stdout.WriteString(value + "\n")
		}
	}
	os.Exit(0)
}

func helperCommand(ctx context.Context, helper string, opts ...subprocess.Option) *exec.Cmd {
	return subprocess.Command(ctx, os.Args[0], []string{"-test.run=^" + helper + "$"}, opts...)
}

func childEnv(t *testing.T, cmd *exec.Cmd) []string {
	t.Helper()
	out, err := cmd.Output()
	require.NoError(t, err)
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n")
}

func childWorkingDir(t *testing.T, cmd *exec.Cmd) (string, string) {
	t.Helper()
	out, err := cmd.Output()
	require.NoError(t, err)
	// Trim one newline only; PWD may be empty on Windows, leaving an empty second line.
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"), "\n")
	require.Len(t, lines, 2)
	return lines[0], lines[1]
}

func assertSameDir(t *testing.T, want, got string) {
	t.Helper()
	// The temp dir may be a symlink (macOS), so compare resolved paths.
	wantResolved, err := filepath.EvalSymlinks(want)
	require.NoError(t, err)
	gotResolved, err := filepath.EvalSymlinks(got)
	require.NoError(t, err)
	assert.Equal(t, wantResolved, gotResolved)
}

func pwdEntries(env []string) []string {
	var entries []string
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "PWD") {
			entries = append(entries, entry)
		}
	}
	return entries
}

func pwdIsExported() bool {
	return runtime.GOOS != "windows" && runtime.GOOS != "plan9"
}

func hasEntry(env []string, name string) bool {
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func isSnykEntry(entry string) bool {
	key, _, _ := strings.Cut(entry, "=")
	return strings.HasPrefix(strings.ToUpper(key), "SNYK_")
}

func TestCommand_ChildDoesNotInheritSnykVariables(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("SNYK_TOKEN", "secret")
	t.Setenv("Snyk_Oauth_Token", "secret2")
	t.Setenv("KEEP_ME", "1")

	env := childEnv(t, helperCommand(t.Context(), envHelper))

	for _, entry := range env {
		assert.False(t, isSnykEntry(entry), "child inherited %q", entry)
		assert.NotContains(t, entry, "secret", "child received a secret value")
	}
	assert.Contains(t, env, "KEEP_ME=1")
	assert.True(t, hasEntry(env, "PATH"), "child lost PATH")
}

func TestCommand_WithSnykEnvKeepsSnykVariables(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("SNYK_TOKEN", "secret")
	t.Setenv("Snyk_Oauth_Token", "secret2")

	env := childEnv(t, helperCommand(t.Context(), envHelper, subprocess.WithSnykEnv()))

	assert.Contains(t, env, "SNYK_TOKEN=secret")
	assert.Contains(t, env, "Snyk_Oauth_Token=secret2")
}

func TestCommand_ArgsReachChild(t *testing.T) {
	t.Setenv(helperEnvVar, "1")

	cmd := subprocess.Command(t.Context(), os.Args[0],
		[]string{"-test.run=^" + argsHelper + "$", "--", "alpha", "beta"})
	assert.Equal(t, []string{os.Args[0], "-test.run=^" + argsHelper + "$", "--", "alpha", "beta"}, cmd.Args)

	out, err := cmd.Output()
	require.NoError(t, err)
	assert.Equal(t, "alpha\nbeta\n", string(out))
}

func TestCommand_NilArgsLeavesOnlyName(t *testing.T) {
	cmd := subprocess.Command(t.Context(), os.Args[0], nil)

	assert.Equal(t, []string{os.Args[0]}, cmd.Args)
}

func TestCommand_WithPWDSetsWorkingDirAndAbsolutePWD(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("PWD", staleParentPWD)
	dir := t.TempDir()
	want, err := filepath.Abs(dir)
	require.NoError(t, err)

	cmd := helperCommand(t.Context(), dirHelper, subprocess.WithPWD(dir))
	assert.Equal(t, dir, cmd.Dir)
	wd, pwd := childWorkingDir(t, cmd)

	assertSameDir(t, want, wd)
	if pwdIsExported() {
		assert.Equal(t, want, pwd)
	}
}

func TestCommand_WithPWDRelativeDirExportsAbsolutePWD(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	base := t.TempDir()
	t.Chdir(base)
	require.NoError(t, os.Mkdir("sub", 0o755))
	want, err := filepath.Abs("sub")
	require.NoError(t, err)

	cmd := helperCommand(t.Context(), dirHelper, subprocess.WithPWD("sub"))
	assert.Equal(t, "sub", cmd.Dir)
	wd, pwd := childWorkingDir(t, cmd)

	assertSameDir(t, want, wd)
	if pwdIsExported() {
		assert.Equal(t, want, pwd)
	}
}

func TestCommand_WithoutPWDRemovesInheritedPWD(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("PWD", staleParentPWD)
	t.Setenv("pwd", staleParentPWD)

	cmd := helperCommand(t.Context(), dirHelper)

	assert.Empty(t, cmd.Dir)
	assert.Empty(t, pwdEntries(cmd.Env))
	assert.Empty(t, pwdEntries(childEnv(t, helperCommand(t.Context(), envHelper))))
}

func TestCommand_WithSnykEnvRemovesInheritedPWD(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("PWD", staleParentPWD)
	t.Setenv("SNYK_TOKEN", "secret")

	cmd := helperCommand(t.Context(), envHelper, subprocess.WithSnykEnv())

	assert.Empty(t, pwdEntries(cmd.Env))
	env := childEnv(t, cmd)
	assert.Empty(t, pwdEntries(env))
	assert.Contains(t, env, "SNYK_TOKEN=secret")
}

func TestCommand_WithPWDExportsOnlyOnePWDEntry(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("PWD", staleParentPWD)
	dir := t.TempDir()

	cmd := helperCommand(t.Context(), dirHelper, subprocess.WithPWD(dir))

	if !pwdIsExported() {
		assert.Empty(t, pwdEntries(cmd.Env))
		return
	}
	want, err := filepath.Abs(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"PWD=" + want}, pwdEntries(cmd.Env))
}

func TestCommand_AppendedVariablesReachChild(t *testing.T) {
	t.Setenv(helperEnvVar, "1")

	cmd := helperCommand(t.Context(), envHelper)
	cmd.Env = append(cmd.Env, "EXTRA_VAR=1")
	env := childEnv(t, cmd)

	assert.Contains(t, env, "EXTRA_VAR=1")
}

func TestCommand_ProcessEnvironmentIsUnchanged(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("SNYK_TOKEN", "secret")
	t.Setenv("PWD", staleParentPWD)

	_ = childEnv(t, helperCommand(t.Context(), envHelper, subprocess.WithPWD(t.TempDir())))

	assert.Equal(t, "secret", os.Getenv("SNYK_TOKEN"))
	assert.Equal(t, staleParentPWD, os.Getenv("PWD"))
}

func TestCommand_HonorsCancelledContext(t *testing.T) {
	t.Setenv(helperEnvVar, "1")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cmd := helperCommand(ctx, envHelper)

	require.Error(t, cmd.Run())
}

func TestCommand_SetsNonNilEnvWithoutSnykEntries(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "secret")

	cmd := helperCommand(t.Context(), envHelper)

	require.NotNil(t, cmd.Env)
	for _, entry := range cmd.Env {
		assert.False(t, isSnykEntry(entry), "cmd.Env contains %q", entry)
	}
}

func TestCommand_DoesNotStartProcess(t *testing.T) {
	cmd := helperCommand(t.Context(), envHelper, subprocess.WithPWD(t.TempDir()))

	assert.Nil(t, cmd.Process)
	assert.Nil(t, cmd.ProcessState)
}

func TestCommand_CombinedOptions(t *testing.T) {
	t.Setenv(helperEnvVar, "1")
	t.Setenv("SNYK_TOKEN", "secret")
	t.Setenv("PWD", staleParentPWD)
	dir := t.TempDir()
	want, err := filepath.Abs(dir)
	require.NoError(t, err)

	cmd := subprocess.Command(t.Context(), os.Args[0],
		[]string{"-test.run=^" + dirHelper + "$"},
		subprocess.WithPWD(dir),
		subprocess.WithSnykEnv(),
	)
	cmd.Env = append(cmd.Env, "EXTRA_VAR=1")

	assert.Contains(t, cmd.Env, "SNYK_TOKEN=secret")
	assert.Contains(t, cmd.Env, "EXTRA_VAR=1")
	wd, pwd := childWorkingDir(t, cmd)

	assertSameDir(t, want, wd)
	if pwdIsExported() {
		assert.Equal(t, want, pwd)
	}
}
