package localworkflows

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Code_legacyImplementation_happyPath(t *testing.T) {
	expectedData := "Hello World"
	flagString := "--user-=bla"
	callback1 := func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		typeId := workflow.NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
		d := workflow.NewData(typeId, "text/plain", expectedData)
		assert.Equal(t, []string{flagString}, invocation.GetConfiguration().Get(configuration.RAW_CMD_ARGS))
		return []workflow.Data{d}, nil
	}

	// set
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, false)

	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	// Create legacycli workflow
	mockLegacyCliWorkflowId := workflow.NewWorkflowIdentifier("legacycli")
	entry1, err := engine.Register(mockLegacyCliWorkflowId, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("1", pflag.ExitOnError)), callback1)
	assert.Nil(t, err)
	assert.NotNil(t, entry1)

	err = engine.Init()
	assert.NoError(t, err)

	// Method under test
	wrkflw, ok := engine.GetWorkflow(WORKFLOWID_CODE)
	assert.True(t, ok)
	assert.NotNil(t, wrkflw)

	os.Args = []string{"cmd", flagString}

	rs, err := engine.InvokeWithConfig(WORKFLOWID_CODE, config)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, expectedData, rs[0].GetPayload().(string))
}

func Test_Code_legacyImplementation_experimentalFlag(t *testing.T) {
	expectedData := "Hello World"

	// Verify that the experimental flag is not passed to the legacycli workflow
	// and the legacycli workflow is invoked with the --json arguments
	mockLegacyWorkFlowFn := func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		typeId := workflow.NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
		d := workflow.NewData(typeId, "text/plain", expectedData)
		assert.Equal(t, []string{"--json", "--severity-threshold=medium"}, invocation.GetConfiguration().Get(configuration.RAW_CMD_ARGS))
		return []workflow.Data{d}, nil
	}

	//
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	// Create legacycli workflow
	mockLegacyCliWorkflowId := workflow.NewWorkflowIdentifier("legacycli")
	entry1, err := engine.Register(mockLegacyCliWorkflowId, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("1", pflag.ExitOnError)), mockLegacyWorkFlowFn)
	assert.Nil(t, err)
	assert.NotNil(t, entry1)

	err = engine.Init()
	assert.NoError(t, err)

	// Method under test
	wrkflw, ok := engine.GetWorkflow(WORKFLOWID_CODE)
	assert.True(t, ok)
	assert.NotNil(t, wrkflw)

	os.Args = []string{"cmd", "--severity-threshold=medium", "--experimental", "--json"}

	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])

	rs, err := engine.InvokeWithConfig(WORKFLOWID_CODE, config)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, expectedData, rs[0].GetPayload().(string))
}

func Test_Code_legacyImplementation_experimentalFlagAndReport(t *testing.T) {
	expectedData := "Hello World"

	// Verify that the experimental path is not taken when the --report flag is passed
	mockLegacyWorkFlowFn := func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		typeId := workflow.NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
		d := workflow.NewData(typeId, "text/plain", expectedData)
		assert.Equal(t, []string{"--severity-threshold=medium", "--report"}, invocation.GetConfiguration().Get(configuration.RAW_CMD_ARGS))
		return []workflow.Data{d}, nil
	}

	//
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	// Create legacycli workflow
	mockLegacyCliWorkflowId := workflow.NewWorkflowIdentifier("legacycli")
	entry1, err := engine.Register(mockLegacyCliWorkflowId, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("1", pflag.ExitOnError)), mockLegacyWorkFlowFn)
	assert.Nil(t, err)
	assert.NotNil(t, entry1)

	err = engine.Init()
	assert.NoError(t, err)

	// Method under test
	wrkflw, ok := engine.GetWorkflow(WORKFLOWID_CODE)
	assert.True(t, ok)
	assert.NotNil(t, wrkflw)

	os.Args = []string{"cmd", "--severity-threshold=medium", "--report"}

	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])

	rs, err := engine.InvokeWithConfig(WORKFLOWID_CODE, config)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, expectedData, rs[0].GetPayload().(string))
}

func Test_Code_nativeImplementation(t *testing.T) {
	expectedSummary := json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 3, Open: 2, Ignored: 1},
			{Severity: "medium", Total: 1, Open: 1},
		},
	}

	config := configuration.NewInMemory()
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess)
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))

	analysisFunc := func(string, func() *http.Client, *zerolog.Logger, configuration.Configuration) (*sarif.SarifResponse, error) {
		response := &sarif.SarifResponse{
			Sarif: sarif.SarifDocument{
				Runs: []sarif.Run{
					{
						Results: []sarif.Result{
							{Level: "error"},
							{Level: "warning"},
						},
					},
					{
						Results: []sarif.Result{
							{Level: "error"},
							{Level: "error", Suppressions: make([]sarif.Suppression, 1)},
						},
					},
				},
			},
		}
		return response, nil
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, 2, len(rs))

	for _, v := range rs {
		if v.GetContentType() == content_type.TEST_SUMMARY {
			actualSummary := &json_schemas.TestSummary{}
			err = json.Unmarshal(v.GetPayload().([]byte), actualSummary)
			assert.NoError(t, err)

			count := 0
			for _, expectedResult := range expectedSummary.Results {
				for _, actualResult := range actualSummary.Results {
					if expectedResult.Severity == actualResult.Severity {
						assert.Equal(t, expectedResult, actualResult)
						count++
					}
				}
			}
			assert.Equal(t, len(expectedSummary.Results), count)
		} else if v.GetContentType() == code_workflow.SARIF_CONTENT_TYPE {
			_, ok := v.GetPayload().([]byte)
			assert.True(t, ok)
		} else {
			assert.Fail(t, "unexpected data")
		}
	}
}
