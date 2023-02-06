package localworkflows

import (
	"log"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

type mockClient struct {
	res interface{}
	err error
}

var mockClientImpl = &mockClient{}

func (m *mockClient) Get() (interface{}, error) {
	return m.res, m.err
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_returnsUserName(t *testing.T) {
	// setup
	payload := `
	{
	"id": "88c4a3b3-ac23-4cbe-8c28-228ff614910b",
	"username": "user.name@snyk.io",
	"email": "user.email@snyk.io",
	"orgs": [
		{
		"name": "Snyk AppSec",
		"id": "4a3d29ab-6612-481b-83f2-aea6cf421ea5",
		"group": {
			"name": "snyk-sec-prod",
			"id": "dd36a3c3-0e57-4702-81e6-a0e099e045a0"
		}
		}
	]
	}
	`
	// expected response
	res := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, workflowName),
		mimeTypeJSON,
		"user.name@snyk.io",
	)

	// setup mocks
	ctrl := gomock.NewController(t)

	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)

	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	newMockClientImpl := &mockClient{
		res: payload,
		err: nil,
	}

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(newMockClientImpl).AnyTimes()

	// execute
	output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

	// assert
	assert.Nil(t, err)
	assert.Equal(t, []workflow.Data{res}, output)
}
