package workflow

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// fakeFlagsConfig validates that certain flags aren't used together
type fakeFlagsConfig struct{}

func (c *fakeFlagsConfig) ValidatePreParse(rawArgs []string) error {
	hasJSON := false
	hasSARIF := false

	for _, arg := range rawArgs {
		if strings.HasPrefix(arg, "--json") {
			hasJSON = true
		}
		if strings.HasPrefix(arg, "--sarif") {
			hasSARIF = true
		}
	}

	if hasJSON && hasSARIF {
		return fmt.Errorf("cannot use --json and --sarif together")
	}

	return nil
}

func TestValidatePreParse(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.New())

	// Setup workflows
	_, err := engine.Register(
		NewWorkflowIdentifier("test"),
		&fakeFlagsConfig{},
		func(InvocationContext, []Data) ([]Data, error) { return nil, nil },
	)
	assert.NoError(t, err)

	flagset := pflag.NewFlagSet("noval", pflag.ContinueOnError)
	_, err = engine.Register(
		NewWorkflowIdentifier("noval"),
		ConfigurationOptionsFromFlagset(flagset),
		func(InvocationContext, []Data) ([]Data, error) { return nil, nil },
	)
	assert.NoError(t, err)

	tests := []struct {
		name        string
		command     string
		rawArgs     []string
		wantErr     bool
		errContains string
	}{
		{
			name:    "with validator accepts valid flags",
			command: "test",
			rawArgs: []string{"--json", "output.json"},
		},
		{
			name:        "with validator rejects invalid flags",
			command:     "test",
			rawArgs:     []string{"--json", "--sarif"},
			wantErr:     true,
			errContains: "cannot use --json and --sarif together",
		},
		{
			name:    "without validator no validation",
			command: "noval",
			rawArgs: []string{"--json", "--sarif"},
		},
		{
			name:    "workflow not found",
			command: "nonexistent",
			rawArgs: []string{"--any"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePreParse(engine, tc.command, tc.rawArgs)

			if tc.wantErr {
				assert.NotNil(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
