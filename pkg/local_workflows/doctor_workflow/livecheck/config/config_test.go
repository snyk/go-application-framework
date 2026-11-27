package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

// Only a working directory file exists, and snyk doctor reports it as an ignored file in a configuration warning.
func Test_Check_ReportsTheIgnoredWorkingDirectoryFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(t.TempDir())
	workingDir, err := os.Getwd()
	require.NoError(t, err)
	ignored := filepath.Join(workingDir, "snyk.json")
	require.NoError(t, os.WriteFile(ignored, []byte(`{"org":"attacker-org"}`), 0o644))

	invocationCtx := mocks.NewMockInvocationContext(gomock.NewController(t))
	invocationCtx.EXPECT().GetConfiguration().Return(configuration.NewWithOpts(configuration.WithFiles("snyk")).Clone()).AnyTimes()
	findings := Check(invocationCtx).Findings()

	require.Len(t, findings, 1)
	assert.Equal(t, diagnosis.KindConfigCheck, findings[0].Kind)
	assert.Equal(t, diagnosis.SeverityWarning, findings[0].Severity)
	assert.Contains(t, findings[0].Message, ignored)
}
