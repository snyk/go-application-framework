package code_workflow

import (
	"testing"

	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
)

func Test_filterSarifResultsByCategory(t *testing.T) {
	response := sarif.SarifResponse{}
	run := sarif.Run{}

	expected := sarif.SarifResponse{}
	expectedRun := sarif.Run{}

	rule1 := sarif.Rule{
		ID: "rule1",
		Properties: sarif.RuleProperties{
			Categories: []string{"Security", "API"},
		},
	}

	rule2 := sarif.Rule{
		ID: "rule2",
		Properties: sarif.RuleProperties{
			Categories: []string{"Security"},
		},
	}

	rule3 := sarif.Rule{
		ID: "rule3",
		Properties: sarif.RuleProperties{
			Categories: []string{"Something"},
		},
	}

	result1 := sarif.Result{
		RuleID:  "rule2",
		Message: sarif.ResultMessage{Text: "result1"},
	}

	result2 := sarif.Result{
		RuleID:  "rule1",
		Message: sarif.ResultMessage{Text: "result2"},
	}

	result3 := sarif.Result{
		RuleID:  "rule3",
		Message: sarif.ResultMessage{Text: "result3"},
	}

	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule1)
	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule2)
	run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule3)
	run.Results = append(run.Results, result1)
	run.Results = append(run.Results, result2)
	run.Results = append(run.Results, result3)
	response.Sarif.Runs = append(response.Sarif.Runs, run)
	response.Sarif.Runs = append(response.Sarif.Runs, run)

	expectedRun.Tool.Driver.Rules = append(expectedRun.Tool.Driver.Rules, rule1)
	expectedRun.Tool.Driver.Rules = append(expectedRun.Tool.Driver.Rules, rule3)
	expectedRun.Results = append(expectedRun.Results, result2)
	expectedRun.Results = append(expectedRun.Results, result3)
	expected.Sarif.Runs = append(expected.Sarif.Runs, expectedRun)
	expected.Sarif.Runs = append(expected.Sarif.Runs, expectedRun)

	filter := []string{"API", "Something"}
	filterSarifResultsByCategory(&response, filter)

	assert.Equal(t, expected, response)

	filterEmpty := []string{}
	filterSarifResultsByCategory(&response, filterEmpty)

	assert.Equal(t, expected, response)
}
