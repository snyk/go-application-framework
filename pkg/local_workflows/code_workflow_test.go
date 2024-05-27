package localworkflows

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
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
	config.Set(ConfigurationSastEnabled, true)

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

	config.Set(ConfigurationSastEnabled, true)

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

	config.Set(ConfigurationSastEnabled, true)

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

func Test_Code_nativeImplementation_happyPath(t *testing.T) {
	numberOfArtefacts := rand.IntN(100)
	expectedSummary := json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 3, Open: 2, Ignored: 1},
			{Severity: "medium", Total: 1, Open: 1},
			{Severity: "low", Total: 1, Open: 0, Ignored: 1},
		},
		Artifacts: numberOfArtefacts,
	}

	expectedRepoUrl := "https://hello.world"
	expectedPath := "/var/lib/something"

	config := configuration.NewInMemory()
	config.Set(code_workflow.RemoteRepoUrlFlagname, expectedRepoUrl)
	config.Set(configuration.INPUT_DIRECTORY, expectedPath)

	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess)
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))

	analysisFunc := func(target scan.Target, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration) (*sarif.SarifResponse, error) {
		assert.Equal(t, expectedPath, target.GetPath())
		assert.Equal(t, expectedRepoUrl, target.(*scan.RepositoryTarget).GetRepositoryUrl())

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
					{
						Results: []sarif.Result{
							{Level: "note", Suppressions: make([]sarif.Suppression, 1)},
						},
					},
				},
			},
			Coverage: []sarif.SarifCoverage{
				{
					Files:       numberOfArtefacts,
					IsSupported: true,
					Lang:        "javascript",
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
			assert.Equal(t, expectedSummary.Artifacts, actualSummary.Artifacts)
		} else if v.GetContentType() == content_type.SARIF_JSON {
			_, ok := v.GetPayload().([]byte)
			assert.True(t, ok)
		} else {
			assert.Fail(t, "unexpected data")
		}
	}
}

func Test_Code_nativeImplementation_analysisFails(t *testing.T) {
	config := configuration.NewInMemory()
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess)
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))

	analysisFunc := func(scan.Target, func() *http.Client, *zerolog.Logger, configuration.Configuration) (*sarif.SarifResponse, error) {
		return nil, fmt.Errorf("something went wrong")
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.Error(t, err)
	assert.Nil(t, rs)
}
