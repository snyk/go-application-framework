package instrumentation_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_DetermineCategory(t *testing.T) {
	args := []string{"application", "whoami", "--experimental", "-d"}
	expected := []string{"whoami", "experimental"}

	engine := workflow.NewWorkFlowEngine(configuration.NewInMemory())
	err := localworkflows.Init(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	actual := instrumentation.DetermineCategory(args, engine)
	assert.Equal(t, expected, actual)
}
