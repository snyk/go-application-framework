package ufm

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_CreateAndRetrieveDataFromUFM(t *testing.T) {
	testID := uuid.New()
	ctlr := gomock.NewController(t)
	singleResult := mocks.NewMockTestResult(ctlr)
	singleResult.EXPECT().GetTestID().Return(&testID).AnyTimes()

	results := []testapi.TestResult{singleResult}

	data := CreateData(workflow.NewWorkflowIdentifier("myflow`"), results)
	assert.NotNil(t, data)

	tmp := GetTestResults(data)
	assert.NotNil(t, tmp)
	assert.Equal(t, len(results), len(tmp))
	assert.Equal(t, results[0].GetTestID(), tmp[0].GetTestID())
}
