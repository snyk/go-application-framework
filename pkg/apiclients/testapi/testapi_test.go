package testapi_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// Helper function to set up a common test scenario with mock server configuration.
// It returns the configured handler, orgID, jobID, testID, and common expected values.
type TestData struct {
	OrgID                    uuid.UUID
	JobID                    uuid.UUID
	TestID                   uuid.UUID
	PollCounter              *atomic.Int32
	FindingsEndpointCalled   *atomic.Bool
	FindingsPageCount        *atomic.Int32
	TestSubjectCreate        testapi.TestSubjectCreate
	ExpectedTestSubject      testapi.TestSubject
	ExpectedSubjectLocators  *[]testapi.TestSubjectLocator
	ExpectedTestConfig       *testapi.TestConfiguration
	ExpectedCreatedAt        time.Time
	ExpectedEffectiveSummary *testapi.FindingSummary
	ExpectedRawSummary       *testapi.FindingSummary
}

func setupTestScenario(t *testing.T) TestData {
	t.Helper()
	orgID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	pollCounter := &atomic.Int32{}
	findingsEndpointCalled := &atomic.Bool{}
	findingsPageCount := &atomic.Int32{}

	testSubjectCreate := newDepGraphTestSubject(t)

	// Convert testSubjectCreate (TestSubjectCreate) to TestSubject for assertions
	var err error
	depGraphSubjectCreate, err := testSubjectCreate.AsDepGraphSubjectCreate()
	require.NoError(t, err)
	expectedTestSubject := testapi.TestSubject{} // Declare here
	err = expectedTestSubject.FromDepGraphSubject(testapi.DepGraphSubject{
		Locator: depGraphSubjectCreate.Locator,
		Type:    testapi.DepGraphSubjectTypeDepGraph,
	})
	require.NoError(t, err)

	expectedTestConfig := &testapi.TestConfiguration{}
	expectedCreatedAt := time.Now().Truncate(time.Second)
	expectedSubjectLocators := &[]testapi.TestSubjectLocator{
		{},
	}
	err = (*expectedSubjectLocators)[0].FromLocalPathLocator(testapi.LocalPathLocator{
		Paths: []string{"pkg:golang/github.com/snyk/go-application-framework@v0.0.0"},
		Type:  testapi.LocalPath,
	})
	require.NoError(t, err)

	expectedEffectiveSummary := &testapi.FindingSummary{Count: 0}
	expectedRawSummary := &testapi.FindingSummary{Count: 0}

	return TestData{
		OrgID:                    orgID,
		JobID:                    jobID,
		TestID:                   testID,
		PollCounter:              pollCounter,
		FindingsEndpointCalled:   findingsEndpointCalled,
		FindingsPageCount:        findingsPageCount,
		TestSubjectCreate:        testSubjectCreate,
		ExpectedTestSubject:      expectedTestSubject,
		ExpectedSubjectLocators:  expectedSubjectLocators,
		ExpectedTestConfig:       expectedTestConfig,
		ExpectedCreatedAt:        expectedCreatedAt,
		ExpectedEffectiveSummary: expectedEffectiveSummary,
		ExpectedRawSummary:       expectedRawSummary,
	}
}

// Basic test that underlying client throws no errors on creation
func Test_CreateClient_Defaults(t *testing.T) {
	// Arrange
	t.Parallel()
	serverURL := "https://test.snyk.io/"
	httpClient := &http.Client{}

	// Act
	testClient, err := testapi.NewTestClient(
		serverURL,
		testapi.WithCustomHTTPClient(httpClient),
	)

	// Assert
	assert.NotEmpty(t, testClient)
	assert.Nil(t, err)
}

// Create TestClient with a custom config, call StartTest, get back 202 Accepted.
func Test_StartTest_Success(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	// Define LocalPolicy
	riskScoreThreshold := uint16(750)
	localPolicy := &testapi.LocalPolicy{
		RiskScoreThreshold: &riskScoreThreshold,
	}

	params := testapi.StartTestParams{
		OrgID:       testData.OrgID.String(),
		Subject:     testData.TestSubjectCreate,
		LocalPolicy: localPolicy,
	}

	// Define expected request body that StartTest should generate
	expectedRequestBody := testapi.TestRequestBody{
		Data: testapi.TestDataCreate{
			Attributes: testapi.TestAttributesCreate{
				Subject: params.Subject,
				Config: &testapi.TestConfiguration{
					LocalPolicy: localPolicy,
				},
			},
			Type: testapi.Tests,
		},
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:                  testData.OrgID,
		JobID:                  testData.JobID,
		TestID:                 testData.TestID,
		APIVersion:             testapi.DefaultAPIVersion,
		ExpectedCreateTestBody: &expectedRequestBody,
		PollCounter:            testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Pass,
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
		FindingsConfig: &FindingsHandlerConfig{
			APIVersion:         testapi.DefaultAPIVersion,
			PageCounter:        testData.FindingsPageCount,
			EndpointCalled:     testData.FindingsEndpointCalled,
			TotalFindingsPages: 0, // Simulate 0 pages of findings
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act

	// Create our test client
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithPollInterval(1*time.Second),
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	assert.NoError(t, err)
	assert.NotNil(t, handle)

	// Verify metadata response is nil before Wait() is called
	initialResult := handle.Result()
	assert.Nil(t, initialResult)

	// Now wait for test to complete and fetch the metadata
	err = handle.Wait(ctx)
	result := handle.Result()

	// Assert final status after Wait()
	assert.NoError(t, err)
	require.NotNil(t, result, "Result should not be nil after successful Wait()")
	assertTestOutcomePass(t, result, testData.TestID)
	assertCommonTestResultFields(t, result, testData.TestID, testData.ExpectedTestConfig, testData.ExpectedTestSubject, testData.ExpectedSubjectLocators, testData.ExpectedEffectiveSummary, testData.ExpectedRawSummary)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2))

	// Fetch and check findings
	findingsResult, complete, findingsErr := result.Findings(ctx)
	assertTestNoFindings(t, findingsResult, complete, findingsErr, testData.FindingsEndpointCalled, testData.FindingsPageCount)
}

// StartTest fails when OrgID is not a UUID
func Test_StartTest_Error_InvalidOrgID(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testSubject := newDepGraphTestSubject(t)
	params := testapi.StartTestParams{
		OrgID:   "not-a-valid-uuid",
		Subject: testSubject,
	}

	// Act: OrgID error occurs before network setup so client can point anywhere
	testClient, err := testapi.NewTestClient("http://localhost:12345")
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "invalid OrgID format")
}

// StartTest returns error from 400 Bad Request
func Test_StartTest_Error_ApiFailure(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()

	// Define mock server's error response body
	errorCode := "SNYK-TEST-4001"
	errorResponse := testapi.IoSnykApiCommonErrorDocument{
		Jsonapi: testapi.IoSnykApiCommonJsonApi{Version: testapi.N10},
		Errors: []testapi.IoSnykApiCommonError{
			{Detail: "Invalid subject provided", Status: "400", Code: &errorCode},
		},
	}

	// Create server to return 400 Bad Request from POST /tests
	handler := newApiErrorResponder(t, orgID, http.StatusBadRequest, errorResponse)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - fail to run StartTest()
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL, testapi.WithCustomHTTPClient(testHTTPClient))
	require.NoError(t, err)

	testSubject := newDepGraphTestSubject(t)
	params := testapi.StartTestParams{OrgID: orgID.String(), Subject: testSubject}

	handle, err := testClient.StartTest(ctx, params)

	// Assert - check the 400 err
	require.Error(t, err)
	assert.Nil(t, handle)

	var sErr snyk_errors.Error
	require.True(t, errors.As(err, &sErr))
	assert.Contains(t, sErr.Detail, "Invalid subject provided")
	assert.Equal(t, "SNYK-TEST-4001", sErr.ErrorCode)
	assert.Equal(t, 400, sErr.StatusCode)
}

// Calling StartTest with a non-listening server returns an error
func Test_StartTest_Error_Network(t *testing.T) {
	// Arrange
	t.Parallel()

	// Use a short timeout to ensure test doesn't hang
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Act

	// Point to a non-listening port
	testClient, err := testapi.NewTestClient("http://127.0.0.1:1")
	require.NoError(t, err, "NewTestClient should not error for a non-listening port if HTTPClient is not immediately used")

	testSubject := newDepGraphTestSubject(t)
	params := testapi.StartTestParams{OrgID: uuid.New().String(), Subject: testSubject}

	handle, err := testClient.StartTest(ctx, params)

	// Assert - could not connect
	assert.Error(t, err)
	assert.Nil(t, handle)

	assert.True(t, strings.Contains(err.Error(), "failed to send create test request") ||
		strings.Contains(err.Error(), "context deadline exceeded") ||
		strings.Contains(err.Error(), "connection refused"))
}

// Synchronous Wait() - start a test with default config, wait for 303 redirect, check
// for "Pass" outcome, then fetch findings.  There is 1 finding with Severity High.
func Test_Wait_Synchronous_Success_Pass_WithFindings(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	startParams := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	testData.ExpectedEffectiveSummary.Count = 1
	testData.ExpectedRawSummary.Count = 1

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      testData.TestID,
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects to final result
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Pass, // Final outcome is Pass
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
		FindingsConfig: &FindingsHandlerConfig{
			APIVersion:         testapi.DefaultAPIVersion,
			PageCounter:        testData.FindingsPageCount,
			EndpointCalled:     testData.FindingsEndpointCalled,
			TotalFindingsPages: 1, // Simulate 1 page of findings, then an empty page (handler will manage nextLink logic)
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - first fetch test result metadata, then fetch findings

	testHTTPClient := newTestHTTPClient(t, server)

	hlClient, err := testapi.NewTestClient(server.URL,
		testapi.WithPollInterval(1*time.Second),
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	// Start the test using the high-level client
	handle, err := hlClient.StartTest(ctx, startParams)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)
	result := handle.Result()

	// Assert initial test completion (Pass)
	assert.NoError(t, err)
	require.NotNil(t, result, "Result should not be nil after successful Wait()")
	assertTestOutcomePass(t, result, testData.TestID)
	assertCommonTestResultFields(t, result, testData.TestID, testData.ExpectedTestConfig, testData.ExpectedTestSubject, testData.ExpectedSubjectLocators, testData.ExpectedEffectiveSummary, testData.ExpectedRawSummary)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2))

	// Fetch and check findings. Ensure pagination is used.
	findingsResult, complete, findingsErr := result.Findings(ctx)
	assertTestOneHighSeverityFinding(t, findingsResult, complete, findingsErr, testData.FindingsEndpointCalled, testData.FindingsPageCount, 2, "Expected findings endpoint to be called twice for pagination")
}

// Test synchronous Wait() successfully completing a test that fails.
func Test_Wait_Synchronous_Success_Fail(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)
	failReason := testapi.TestOutcomeReasonPolicyBreach

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      testData.TestID,
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Fail,
			OutcomeReason:     &failReason,
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start test and wait for results with a Fail outcome
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert - state: Finished, outcome: Failed and with failReason
	assert.NoError(t, err)
	require.NotNil(t, result, "Result should not be nil after successful Wait()")
	assertTestOutcomeFail(t, result, testData.TestID, failReason)
	assertCommonTestResultFields(t, result, testData.TestID, testData.ExpectedTestConfig, testData.ExpectedTestSubject, testData.ExpectedSubjectLocators, testData.ExpectedEffectiveSummary, testData.ExpectedRawSummary)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2))
}

// Asynchronous Wait() - start a test, wait for 303 redirect, and check for "Pass" outcome.
func Test_Wait_Asynchronous_Success_Pass(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	// Define expected request body that StartTest should generate
	expectedRequestBody := testapi.TestRequestBody{
		Data: testapi.TestDataCreate{
			Attributes: testapi.TestAttributesCreate{Subject: params.Subject},
			Type:       testapi.Tests,
		},
	}

	handlerConfig := TestAPIHandlerConfig{
		OrgID:                  testData.OrgID,
		JobID:                  testData.JobID,
		TestID:                 testData.TestID,
		APIVersion:             testapi.DefaultAPIVersion,
		ExpectedCreateTestBody: &expectedRequestBody,
		PollCounter:            testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending},
			{ShouldRedirect: true},
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Pass,
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
		FindingsConfig: &FindingsHandlerConfig{
			APIVersion:         testapi.DefaultAPIVersion,
			PageCounter:        testData.FindingsPageCount,
			EndpointCalled:     testData.FindingsEndpointCalled,
			TotalFindingsPages: 0, // Simulate 0 pages of findings
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithPollInterval(1*time.Second), // Keep poll interval short for tests
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Wait asynchronously
	go func() {
		waitErr := handle.Wait(ctx)
		assert.NoError(t, waitErr)
	}()

	var result testapi.TestResult
	select {
	case <-handle.Done():
		result = handle.Result()
	case <-time.After(5 * time.Second): // Generous timeout for test
		t.Fatal("Timed out waiting for handle.Done()")
	}

	// Assert - state: Finished, outcome: Pass
	require.NotNil(t, result, "Result should not be nil after successful Wait()/Done()")
	assertTestOutcomePass(t, result, testData.TestID)
	assertCommonTestResultFields(t, result, testData.TestID, testData.ExpectedTestConfig, testData.ExpectedTestSubject, testData.ExpectedSubjectLocators, testData.ExpectedEffectiveSummary, testData.ExpectedRawSummary)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2))

	// Fetch and check findings
	findingsResultAsync, findingsComplete, findingsErrAsync := result.Findings(ctx)
	assertTestNoFindings(t, findingsResultAsync, findingsComplete, findingsErrAsync, testData.FindingsEndpointCalled, testData.FindingsPageCount)
}

// Test that synchronous Wait() returns a polling error from the second GET job request.
func Test_Wait_Synchronous_JobErrored(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      uuid.New(), // unused in this test but required
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{Status: testapi.Errored}, // Second poll, job reports errored
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Pass, // Placeholder, not reached
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test and Wait() returns a polling error
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("job reported status 'errored' (jobID: %s)", testData.JobID))
	assert.Contains(t, err.Error(), "polling job failed")
	assert.Nil(t, result)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2))
}

// Test asynchronous Wait() when polling times out due to context cancellation.
// Polling is every 1 sec. The Wait context times out at 1.2 sec, before it gets a response.
func Test_Wait_Asynchronous_PollingTimeout(t *testing.T) {
	// Arrange
	t.Parallel()
	// Short context timeout -- allows for at least one GET job poll
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	testData := setupTestScenario(t)

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      uuid.New(), // Not reached in this test
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{ // First poll: slow it down so Wait() can time out first
				CustomHandler: func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(1500 * time.Millisecond)
					jobResp := mockJobStatusResponse(t, testData.JobID, testapi.Pending)
					w.WriteHeader(http.StatusOK)
					_, errWrite := w.Write(jobResp)
					assert.NoError(t, errWrite)
				},
			},
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Pass, // unused placeholder
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)

	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test client with short poll interval
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithPollInterval(1*time.Second),
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	// StartTest is on a background context so it's not affected by ctx's short timeout
	handle, err := testClient.StartTest(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	errChannel := make(chan error, 1)
	go func() {
		// Wait will fail due to ctx's timeout before the server can respond
		errChannel <- handle.Wait(ctx)
		close(errChannel)
	}()

	var result testapi.TestResult
	select {
	case <-handle.Done():
		result = handle.Result()
	case <-time.After(2000 * time.Millisecond): // timeout for entire test; should not be reached
		t.Fatal("Unexpected timeout waiting for handle.Done()")
	}

	waitErr := <-errChannel
	// Assert - Wait returns an error; timeout occurs while it waits on the HTTP response
	assert.Error(t, waitErr)
	assert.ErrorIs(t, waitErr, context.DeadlineExceeded)
	assert.Contains(t, waitErr.Error(), "context deadline exceeded")
	assert.Nil(t, result)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(1))
}

// Test synchronous Wait() when fetching the final test result fails (e.g., 404).
func Test_Wait_Synchronous_FetchResultFails(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      testData.TestID,
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll: Pending
			{ShouldRedirect: true},    // Second poll: Redirect
		},
		FinalTestResult: FinalTestResultConfig{
			CustomHandler: func(w http.ResponseWriter, r *http.Request) {
				// final result simulates a 404
				http.Error(w, "Test Result Not Found by CustomHandler", http.StatusNotFound)
			},
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
			BreachedPolicies:  nil,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test but get 404 when waiting on it
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert - Wait returns an error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch final test status: Client request cannot be processed")

	var sErr snyk_errors.Error
	require.True(t, errors.As(err, &sErr))
	assert.Contains(t, sErr.Detail, "fetching test result")
	assert.Contains(t, sErr.Detail, "status: 404")
	assert.Nil(t, result)
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2))
}

// Synchronous Wait() for a test with a failure result, API errors, and warnings.
func Test_Wait_Synchronous_Finished_With_ErrorsAndWarnings(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	expectedAPIErrors := &[]testapi.IoSnykApiCommonError{
		{Detail: "Test error 1", Status: "500", Code: ptr("SNYK-ERROR-4001")},
		{Detail: "Test error 2", Status: "400", Code: ptr("SNYK-ERROR-4002"), Title: ptr("Error 2")},
	}
	expectedAPIWarnings := &[]testapi.IoSnykApiCommonError{
		{Detail: "Test warning 1", Status: "200", Code: ptr("SNYK-WARN-4003")},
		{Detail: "Test warning 2", Status: "200", Code: ptr("SNYK-WARN-4004"), Title: ptr("Warning 2")},
	}
	failReason := testapi.TestOutcomeReasonPolicyBreach
	expectedBreachedPolicies := &testapi.PolicyRefSet{
		Ids:         []uuid.UUID{uuid.New()},
		LocalPolicy: ptr(true),
	}

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	testData.ExpectedEffectiveSummary.Count = 5 // Example count
	testData.ExpectedRawSummary.Count = 10      // Example count

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      testData.TestID,
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending},
			{ShouldRedirect: true},
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:           testapi.Fail,
			OutcomeReason:     &failReason,
			ApiErrors:         expectedAPIErrors,
			ApiWarnings:       expectedAPIWarnings,
			TestConfiguration: testData.ExpectedTestConfig,
			CreatedAt:         &testData.ExpectedCreatedAt,
			TestSubject:       testData.ExpectedTestSubject,
			SubjectLocators:   testData.ExpectedSubjectLocators,
			BreachedPolicies:  expectedBreachedPolicies,
			EffectiveSummary:  testData.ExpectedEffectiveSummary,
			RawSummary:        testData.ExpectedRawSummary,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test but get 404 when waiting on it
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithPollInterval(1*time.Second),
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert Fail with errors and warnings
	assert.NoError(t, err)
	require.NotNil(t, result, "Result should not be nil after successful Wait()")
	assertTestFinishedWithOutcomeErrorsAndWarnings(t, result, testData.TestID, testapi.Fail, &failReason, expectedAPIErrors, expectedAPIWarnings)
	assertCommonTestResultFields(t, result, testData.TestID, testData.ExpectedTestConfig, testData.ExpectedTestSubject, testData.ExpectedSubjectLocators, testData.ExpectedEffectiveSummary, testData.ExpectedRawSummary)
	require.NotNil(t, result.GetBreachedPolicies())
	assert.Equal(t, expectedBreachedPolicies, result.GetBreachedPolicies())
	assert.GreaterOrEqual(t, testData.PollCounter.Load(), int32(2), "Should have polled at least twice")
}

// Helper function to assert common fields of a TestResult.
func assertCommonTestResultFields(t *testing.T, result testapi.TestResult, expectedTestID uuid.UUID, expectedConfig *testapi.TestConfiguration, expectedSubject testapi.TestSubject, expectedLocators *[]testapi.TestSubjectLocator, expectedEffectiveSummary *testapi.FindingSummary, expectedRawSummary *testapi.FindingSummary) {
	t.Helper()
	require.NotNil(t, result.GetTestID())
	assert.Equal(t, expectedTestID, *result.GetTestID())

	if expectedConfig != nil {
		require.NotNil(t, result.GetTestConfiguration())
		assert.Equal(t, expectedConfig, result.GetTestConfiguration())
	} else {
		assert.Nil(t, result.GetTestConfiguration())
	}

	require.NotNil(t, result.GetCreatedAt()) // Should always be set by the API
	assert.False(t, result.GetCreatedAt().IsZero())

	require.NotNil(t, result.GetTestSubject())
	assert.Equal(t, expectedSubject, result.GetTestSubject())

	if expectedLocators != nil {
		require.NotNil(t, result.GetSubjectLocators())
		assert.Equal(t, *expectedLocators, *result.GetSubjectLocators())
	} else {
		assert.Nil(t, result.GetSubjectLocators())
	}

	if expectedEffectiveSummary != nil {
		require.NotNil(t, result.GetEffectiveSummary())
		assert.Equal(t, expectedEffectiveSummary, result.GetEffectiveSummary())
	} else {
		assert.Nil(t, result.GetEffectiveSummary())
	}

	if expectedRawSummary != nil {
		require.NotNil(t, result.GetRawSummary())
		assert.Equal(t, expectedRawSummary, result.GetRawSummary())
	} else {
		assert.Nil(t, result.GetRawSummary())
	}
}

// Helper function to assert a "Pass" outcome for a test result.
func assertTestOutcomePass(t *testing.T, result testapi.TestResult, expectedTestID uuid.UUID) {
	t.Helper()
	assert.Equal(t, testapi.Finished, result.GetExecutionState())
	require.NotNil(t, result.GetPassFail())
	assert.Equal(t, testapi.Pass, *result.GetPassFail())
	require.NotNil(t, result.GetTestID())
	assert.Equal(t, expectedTestID, *result.GetTestID())
	assert.Nil(t, result.GetOutcomeReason())
	assert.Nil(t, result.GetErrors())
	assert.Nil(t, result.GetWarnings())
	assert.Nil(t, result.GetBreachedPolicies())
}

// Test_NewTestClient_LoggerOption verifies that a custom logger is used when provided.
func Test_NewTestClient_CustomLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	orgID := uuid.New()
	expectedJobIDInLog := uuid.New() // this jobID is logged when a 404 occurs during polling

	// Create a buffer to capture log output and a custom logger
	var logBuffer bytes.Buffer
	customLogger := zerolog.New(&logBuffer).With().Timestamp().Logger()

	// Setup mock server where GET /job/{jobID} returns 404 to trigger a log.
	handlerConfig := TestAPIHandlerConfig{
		OrgID:      orgID,
		JobID:      expectedJobIDInLog,
		TestID:     uuid.New(),
		APIVersion: testapi.DefaultAPIVersion,
		JobPollResponses: []JobPollResponseConfig{
			{
				// First poll attempt for the job will hit this custom handler
				CustomHandler: func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, expectedJobIDInLog.String()) {
						http.Error(w, "Job Not Found by CustomHandler for logger test", http.StatusNotFound)
					} else {
						http.Error(w, "Unexpected jobID in poll request for logger test", http.StatusInternalServerError)
					}
				},
			},
			// Add a fallback response in case the 404 doesn't stop polling as expected by the test's timeout.
			// This ensures Wait() doesn't hang indefinitely if the context timeout is too long or fails.
			{ShouldRedirect: true},
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Create TestClient with the custom logger.
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithLogger(&customLogger),
		testapi.WithPollInterval(1*time.Second),
		testapi.WithCustomHTTPClient(testHTTPClient),
	)
	require.NoError(t, err)

	// Start a test with a minimal subject.
	testSubject := newDepGraphTestSubject(t)
	params := testapi.StartTestParams{OrgID: orgID.String(), Subject: testSubject}

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// pollJobToCompletion will encounter the 404 from our mock, log the warning, and continue polling.
	// The Wait() call will likely terminate due to context deadline.
	waitCtx, cancelWait := context.WithTimeout(ctx, 2*time.Second)
	defer cancelWait()

	_ = handle.Wait(waitCtx) //nolint:errcheck // error expected if context times out

	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "404 Not Found")
}

// Helper function to assert a "Fail" outcome for a test result.
func assertTestOutcomeFail(t *testing.T, result testapi.TestResult, expectedTestID uuid.UUID, expectedReason testapi.TestOutcomeReason) {
	t.Helper()
	assert.Equal(t, testapi.Finished, result.GetExecutionState())
	require.NotNil(t, result.GetPassFail())
	assert.Equal(t, testapi.Fail, *result.GetPassFail())
	require.NotNil(t, result.GetTestID())
	assert.Equal(t, expectedTestID, *result.GetTestID())
	require.NotNil(t, result.GetOutcomeReason())
	assert.Equal(t, expectedReason, *result.GetOutcomeReason())
	assert.Nil(t, result.GetErrors())
	assert.Nil(t, result.GetWarnings())
	assert.Nil(t, result.GetBreachedPolicies())
}

// Helper function to assert that there are no findings.
// Assumes that "no findings" means the findings endpoint is called exactly once.
func assertTestNoFindings(t *testing.T, findingsResult []testapi.FindingData, complete bool, findingsErr error, findingsEndpointCalled *atomic.Bool, findingsPageCount *atomic.Int32) {
	t.Helper()
	assert.NoError(t, findingsErr)
	assert.True(t, complete)
	if findingsEndpointCalled != nil {
		assert.True(t, findingsEndpointCalled.Load())
	}
	if findingsPageCount != nil {
		assert.Equal(t, int32(1), findingsPageCount.Load(), "Expected findings endpoint to be called once for no findings")
	}
	assert.Empty(t, findingsResult)
}

// Helper function to assert one high severity finding.
// Note: This is specific to the current mock data ("XYZ High Sev").
func assertTestOneHighSeverityFinding(t *testing.T, findingsResult []testapi.FindingData, complete bool, findingsErr error, findingsEndpointCalled *atomic.Bool, findingsPageCount *atomic.Int32, expectedPageCount int32, message string) {
	t.Helper()
	assert.NoError(t, findingsErr)
	assert.True(t, complete)
	if findingsEndpointCalled != nil {
		assert.True(t, findingsEndpointCalled.Load())
	}
	if findingsPageCount != nil {
		// Retain the original message for this specific assertion as it was pre-existing in the test
		assert.Equal(t, expectedPageCount, findingsPageCount.Load(), message)
	}

	require.NotNil(t, findingsResult)
	assert.Len(t, findingsResult, 1)
	if len(findingsResult) == 1 { // Check len before accessing to prevent panic
		finding := findingsResult[0]
		require.NotNil(t, finding.Type)
		assert.Equal(t, testapi.Findings, *finding.Type)
		assert.Equal(t, "XYZ High Sev", finding.Attributes.Title)
		assert.Equal(t, testapi.SeverityHigh, finding.Attributes.Rating.Severity)
		assert.Equal(t, uint16(80), finding.Attributes.Risk.RiskScore.Value)
	}
}

// Helper function to assert a finished test with specific outcome, errors, and warnings.
func assertTestFinishedWithOutcomeErrorsAndWarnings(t *testing.T, result testapi.TestResult, expectedTestID uuid.UUID, expectedOutcome testapi.PassFail, expectedReason *testapi.TestOutcomeReason, expectedErrors *[]testapi.IoSnykApiCommonError, expectedWarnings *[]testapi.IoSnykApiCommonError) {
	t.Helper()
	assert.Equal(t, testapi.Finished, result.GetExecutionState())
	require.NotNil(t, result.GetPassFail())
	assert.Equal(t, expectedOutcome, *result.GetPassFail())
	require.NotNil(t, result.GetTestID())
	assert.Equal(t, expectedTestID, *result.GetTestID())

	if expectedReason != nil {
		require.NotNil(t, result.GetOutcomeReason())
		assert.Equal(t, *expectedReason, *result.GetOutcomeReason())
	} else {
		assert.Nil(t, result.GetOutcomeReason())
	}

	if expectedErrors != nil {
		require.NotNil(t, result.GetErrors())
		assert.Equal(t, *expectedErrors, *result.GetErrors())
	} else {
		assert.Nil(t, result.GetErrors())
	}

	if expectedWarnings != nil {
		require.NotNil(t, result.GetWarnings())
		assert.Equal(t, *expectedWarnings, *result.GetWarnings())
	} else {
		assert.Nil(t, result.GetWarnings())
	}
}

// TestJitter verifies times returned are 0.5-1.5 times the original value,
// and invalid times are return unmodified.
func TestJitter(t *testing.T) {
	t.Parallel()
	t.Run("returns original duration for zero or negative input", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, time.Duration(0), testapi.Jitter(0))
		assert.Equal(t, time.Duration(-1), testapi.Jitter(-1))
	})

	t.Run("returns duration within 0.5x to 1.5x of input", func(t *testing.T) {
		t.Parallel()
		duration := 100 * time.Millisecond
		minDur := time.Duration(float64(duration) * 0.5)
		maxDur := time.Duration(float64(duration) * 1.5)

		for range 100 {
			jittered := testapi.Jitter(duration)
			assert.GreaterOrEqual(t, jittered, minDur)
			assert.LessOrEqual(t, jittered, maxDur)
		}
	})
}

// Test_Wait_CallsJitter ensures Jitter is called while polling for job completion.
func Test_Wait_CallsJitter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testData := setupTestScenario(t)

	params := testapi.StartTestParams{
		OrgID:   testData.OrgID.String(),
		Subject: testData.TestSubjectCreate,
	}

	// Mock Jitter
	var jitterCalled bool
	jitterFunc := func(d time.Duration) time.Duration {
		jitterCalled = true
		return d
	}

	// Mock server handler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       testData.OrgID,
		JobID:       testData.JobID,
		TestID:      testData.TestID,
		APIVersion:  testapi.DefaultAPIVersion,
		PollCounter: testData.PollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome: testapi.Pass,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL,
		testapi.WithPollInterval(1*time.Second),
		testapi.WithCustomHTTPClient(testHTTPClient),
		testapi.WithJitterFunc(jitterFunc),
	)
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)
	require.NoError(t, err)

	// Assert
	assert.True(t, jitterCalled)
}
