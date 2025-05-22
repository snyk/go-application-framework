package testapi_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// Basic test that underlying client throws no errors on creation
func Test_CreateClient_Defaults(t *testing.T) {
	// Arrange
	t.Parallel()
	serverURL := "https://test.snyk.io/"
	httpClient := &http.Client{}

	// Act
	testClient, err := testapi.NewTestClient(
		serverURL,
		testapi.Config{},
		testapi.WithHTTPClient(httpClient),
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
	orgID := uuid.New()
	assetID := uuid.New()
	expectedJobID := uuid.New()
	apiVersion := "2024-10-15"
	finalTestID := uuid.New()
	var pollCounter atomic.Int32 // Used by handler to count GET /job calls
	var findingsEndpointCalled atomic.Bool
	var findingsPageCount atomic.Int32

	// Create a DepGraph to test
	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{OrgID: orgID.String(), Subject: testSubject}

	// Define expected request body that StartTest should generate
	expectedRequestBody := testapi.TestRequestBody{
		Data: testapi.TestDataCreate{
			Attributes: testapi.TestAttributesCreate{Subject: params.Subject},
			Type:       testapi.Tests,
		},
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:                  orgID,
		JobID:                  expectedJobID,
		TestID:                 finalTestID,
		APIVersion:             apiVersion,
		ExpectedCreateTestBody: &expectedRequestBody,
		PollCounter:            &pollCounter,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects
		},
		FinalTestResult: FinalTestResultConfig{Outcome: testapi.Pass},
		FindingsConfig: &FindingsHandlerConfig{
			APIVersion:         apiVersion,
			PageCounter:        &findingsPageCount,
			EndpointCalled:     &findingsEndpointCalled,
			TotalFindingsPages: 0, // Simulate 0 pages of findings
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act

	// Create our test client
	testHTTPClient := newTestHTTPClient(t, server)
	clientConfig := testapi.Config{
		APIVersion:   apiVersion,
		PollInterval: 1 * time.Second, // short poll interval for faster tests
	}
	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
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
	assertTestOutcomePass(t, result, finalTestID)
	assert.GreaterOrEqual(t, pollCounter.Load(), int32(2))

	// Fetch and check findings
	findingsResult, complete, findingsErr := result.Findings(ctx)
	assertTestNoFindings(t, findingsResult, complete, findingsErr, &findingsEndpointCalled, &findingsPageCount)
}

// StartTest fails when OrgID is not a UUID
func Test_StartTest_Error_InvalidOrgID(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()

	testSubject := newDepGraphTestSubject(t, uuid.New())
	params := testapi.StartTestParams{
		OrgID:   "not-a-valid-uuid",
		Subject: testSubject,
	}

	// Act: OrgID error occurs before network setup so client can point anywhere
	testClient, err := testapi.NewTestClient("http://localhost:12345", testapi.Config{})
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
	testClient, err := testapi.NewTestClient(server.URL, testapi.Config{}, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err)

	testSubject := newDepGraphTestSubject(t, uuid.New())
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
	clientConfig := testapi.Config{APIVersion: "2024-10-15"}
	testClient, err := testapi.NewTestClient("http://127.0.0.1:1", clientConfig)
	require.NoError(t, err)

	testSubject := newDepGraphTestSubject(t, uuid.New())
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
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	apiVersion := "2024-10-15"
	var pollCount atomic.Int32
	var findingsEndpointCalled atomic.Bool
	var findingsPageCount atomic.Int32 // To track pagination calls

	testSubject := newDepGraphTestSubject(t, assetID)
	startParams := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       orgID,
		JobID:       jobID,
		TestID:      testID,
		APIVersion:  apiVersion,
		PollCounter: &pollCount,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects to final result
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome: testapi.Pass, // Final outcome is Pass
		},
		FindingsConfig: &FindingsHandlerConfig{
			APIVersion:         apiVersion,
			PageCounter:        &findingsPageCount,
			EndpointCalled:     &findingsEndpointCalled,
			TotalFindingsPages: 1, // Simulate 1 page of findings, then an empty page (handler will manage nextLink logic)
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - first fetch test result metadata, then fetch findings

	testHTTPClient := newTestHTTPClient(t, server)

	clientConfig := testapi.Config{
		APIVersion:   apiVersion,
		PollInterval: 1 * time.Second,
	}
	hlClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
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
	assertTestOutcomePass(t, result, testID)
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2))

	// Fetch and check findings. Ensure pagination is used.
	findingsResult, complete, findingsErr := result.Findings(ctx)
	assertTestOneHighSeverityFinding(t, findingsResult, complete, findingsErr, &findingsEndpointCalled, &findingsPageCount, 2, "Expected findings endpoint to be called twice for pagination")
}

// Test synchronous Wait() successfully completing a test that fails.
func Test_Wait_Synchronous_Success_Fail(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	var pollCount atomic.Int32
	failReason := testapi.TestOutcomeReasonPolicyBreach

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       orgID,
		JobID:       jobID,
		TestID:      testID,
		APIVersion:  "2024-10-15",
		PollCounter: &pollCount,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{ShouldRedirect: true},    // Second poll, redirects
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:       testapi.Fail,
			OutcomeReason: &failReason,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start test and wait for results with a Fail outcome
	testHTTPClient := newTestHTTPClient(t, server)
	clientConfig := testapi.Config{APIVersion: "2024-10-15"} // Ensure client version matches handler
	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert - state: Finished, outcome: Failed and with failReason
	assert.NoError(t, err)
	require.NotNil(t, result, "Result should not be nil after successful Wait()")
	assertTestOutcomeFail(t, result, testID, failReason)
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2))
}

// Asynchronous Wait() - start a test, wait for 303 redirect, and check for "Pass" outcome.
func Test_Wait_Asynchronous_Success_Pass(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	var pollCount atomic.Int32
	var findingsEndpointCalled atomic.Bool
	var findingsPageCount atomic.Int32
	apiVersion := "2024-10-15"

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Define expected request body that StartTest should generate
	expectedRequestBody := testapi.TestRequestBody{
		Data: testapi.TestDataCreate{
			Attributes: testapi.TestAttributesCreate{Subject: params.Subject},
			Type:       testapi.Tests,
		},
	}

	handlerConfig := TestAPIHandlerConfig{
		OrgID:                  orgID,
		JobID:                  jobID,
		TestID:                 testID,
		APIVersion:             apiVersion,
		ExpectedCreateTestBody: &expectedRequestBody,
		PollCounter:            &pollCount,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending},
			{ShouldRedirect: true},
		},
		FinalTestResult: FinalTestResultConfig{Outcome: testapi.Pass},
		FindingsConfig: &FindingsHandlerConfig{
			APIVersion:         apiVersion,
			PageCounter:        &findingsPageCount,
			EndpointCalled:     &findingsEndpointCalled,
			TotalFindingsPages: 0, // Simulate 0 pages of findings
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL, testapi.Config{}, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Wait asynchronously
	go func() {
		waitErr := handle.Wait(ctx)
		assert.NoError(t, waitErr)
	}()

	var result *testapi.Result
	select {
	case <-handle.Done():
		result = handle.Result()
	case <-time.After(5 * time.Second): // Generous timeout for test
		t.Fatal("Timed out waiting for handle.Done()")
	}

	// Assert - state: Finished, outcome: Pass
	// waitErr was asserted NoError before this block
	require.NotNil(t, result, "Result should not be nil after successful Wait()/Done()")
	assertTestOutcomePass(t, result, testID)
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2))

	// Fetch and check findings
	findingsResultAsync, findingsComplete, findingsErrAsync := result.Findings(ctx)
	assertTestNoFindings(t, findingsResultAsync, findingsComplete, findingsErrAsync, &findingsEndpointCalled, &findingsPageCount)
}

// Test that synchronous Wait() returns a polling error from the second GET job request.
func Test_Wait_Synchronous_JobErrored(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	var pollCount atomic.Int32

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       orgID,
		JobID:       jobID,
		TestID:      uuid.New(), // unused in this test but required
		APIVersion:  "2024-10-15",
		PollCounter: &pollCount,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll
			{Status: testapi.Errored}, // Second poll, job reports errored
		},
		FinalTestResult: FinalTestResultConfig{Outcome: testapi.Pass}, // Placeholder, not reached
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test and Wait() returns a polling error
	testHTTPClient := newTestHTTPClient(t, server)
	clientConfig := testapi.Config{APIVersion: "2024-10-15"} // Ensure client version matches handler
	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("job reported status 'errored' (jobID: %s)", jobID))
	assert.Contains(t, err.Error(), "polling job failed")
	assert.Nil(t, result)
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2))
}

// Test asynchronous Wait() when polling times out due to context cancellation.
// Polling is every 1 sec. The Wait context times out at 1.2 sec, before it gets a response.
func Test_Wait_Asynchronous_PollingTimeout(t *testing.T) {
	// Arrange
	t.Parallel()
	// Short context timeout -- allows for at least one GET job poll
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	apiVersion := "2024-10-15"
	var pollCount atomic.Int32

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       orgID,
		JobID:       jobID,
		TestID:      uuid.New(), // Not reached in this test
		APIVersion:  apiVersion,
		PollCounter: &pollCount,
		JobPollResponses: []JobPollResponseConfig{
			{ // First poll: slow it down so Wait() can time out first
				CustomHandler: func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(1500 * time.Millisecond)
					jobResp := mockJobStatusResponse(t, jobID, testapi.Pending)
					w.WriteHeader(http.StatusOK)
					_, errWrite := w.Write(jobResp)
					assert.NoError(t, errWrite)
				},
			},
		},
		FinalTestResult: FinalTestResultConfig{Outcome: testapi.Pass}, // unused placeholder
	}
	handler := newTestAPIMockHandler(t, handlerConfig)

	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test client with short poll interval
	clientConfig := testapi.Config{APIVersion: apiVersion, PollInterval: 1 * time.Second}
	testHTTPClient := newTestHTTPClient(t, server)
	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
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

	var result *testapi.Result
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
	assert.GreaterOrEqual(t, pollCount.Load(), int32(1))
}

// Test synchronous Wait() when fetching the final test result fails (e.g., 404).
func Test_Wait_Synchronous_FetchResultFails(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	var pollCount atomic.Int32

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       orgID,
		JobID:       jobID,
		TestID:      testID,
		APIVersion:  "2024-10-15",
		PollCounter: &pollCount, // Pass the address of pollCount
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending}, // First poll: Pending
			{ShouldRedirect: true},    // Second poll: Redirect
		},
		FinalTestResult: FinalTestResultConfig{
			CustomHandler: func(w http.ResponseWriter, r *http.Request) {
				// This custom handler for the final result simulates a 404
				http.Error(w, "Test Result Not Found by CustomHandler", http.StatusNotFound)
			},
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test but get 404 when waiting on it
	testHTTPClient := newTestHTTPClient(t, server)
	clientConfig := testapi.Config{APIVersion: "2024-10-15"}
	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
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
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2))
}

// Synchronous Wait() for a test with a failure result, API errors, and warnings.
func Test_Wait_Synchronous_Finished_With_ErrorsAndWarnings(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	var pollCount atomic.Int32
	apiVersion := "2024-10-15"

	expectedAPIErrors := &[]testapi.IoSnykApiCommonError{
		{Detail: "Test error 1", Status: "500", Code: ptr("SNYK-ERROR-4001")},
		{Detail: "Test error 2", Status: "400", Code: ptr("SNYK-ERROR-4002"), Title: ptr("Error 2")},
	}
	expectedAPIWarnings := &[]testapi.IoSnykApiCommonError{
		{Detail: "Test warning 1", Status: "200", Code: ptr("SNYK-WARN-4003")},
		{Detail: "Test warning 2", Status: "200", Code: ptr("SNYK-WARN-4004"), Title: ptr("Warning 2")},
	}
	failReason := testapi.TestOutcomeReasonPolicyBreach

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler using newTestAPIMockHandler
	handlerConfig := TestAPIHandlerConfig{
		OrgID:       orgID,
		JobID:       jobID,
		TestID:      testID,
		APIVersion:  apiVersion,
		PollCounter: &pollCount,
		JobPollResponses: []JobPollResponseConfig{
			{Status: testapi.Pending},
			{ShouldRedirect: true},
		},
		FinalTestResult: FinalTestResultConfig{
			Outcome:       testapi.Fail,
			OutcomeReason: &failReason,
			ApiErrors:     expectedAPIErrors,
			ApiWarnings:   expectedAPIWarnings,
		},
	}
	handler := newTestAPIMockHandler(t, handlerConfig)
	server, cleanup := startMockServer(t, handler)
	defer cleanup()

	// Act - start a test but get 404 when waiting on it
	testHTTPClient := newTestHTTPClient(t, server)
	clientConfig := testapi.Config{APIVersion: apiVersion, PollInterval: 1 * time.Second}
	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err)

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	err = handle.Wait(ctx)

	result := handle.Result()

	// Assert Fail with errors and warnings
	assert.NoError(t, err)
	require.NotNil(t, result, "Result should not be nil after successful Wait()")
	assertTestFinishedWithOutcomeErrorsAndWarnings(t, result, testID, testapi.Fail, &failReason, expectedAPIErrors, expectedAPIWarnings)
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2), "Should have polled at least twice")
}

// Helper function to assert a "Pass" outcome for a test result.
func assertTestOutcomePass(t *testing.T, result *testapi.Result, expectedTestID uuid.UUID) {
	t.Helper()
	assert.Equal(t, string(testapi.Finished), result.State)
	require.NotNil(t, result.Outcome)
	assert.Equal(t, testapi.Pass, *result.Outcome)
	require.NotNil(t, result.TestID)
	assert.Equal(t, expectedTestID, *result.TestID)
	assert.Nil(t, result.OutcomeReason)
	assert.Nil(t, result.Errors)
	assert.Nil(t, result.Warnings)
}

// Helper function to assert a "Fail" outcome for a test result.
func assertTestOutcomeFail(t *testing.T, result *testapi.Result, expectedTestID uuid.UUID, expectedReason testapi.TestOutcomeReason) {
	t.Helper()
	assert.Equal(t, string(testapi.Finished), result.State)
	require.NotNil(t, result.Outcome)
	assert.Equal(t, testapi.Fail, *result.Outcome)
	require.NotNil(t, result.TestID)
	assert.Equal(t, expectedTestID, *result.TestID)
	require.NotNil(t, result.OutcomeReason)
	assert.Equal(t, expectedReason, *result.OutcomeReason)
	assert.Nil(t, result.Errors)
	assert.Nil(t, result.Warnings)
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
func assertTestFinishedWithOutcomeErrorsAndWarnings(t *testing.T, result *testapi.Result, expectedTestID uuid.UUID, expectedOutcome testapi.PassFail, expectedReason *testapi.TestOutcomeReason, expectedErrors *[]testapi.IoSnykApiCommonError, expectedWarnings *[]testapi.IoSnykApiCommonError) {
	t.Helper()
	assert.Equal(t, string(testapi.Finished), result.State)
	require.NotNil(t, result.Outcome)
	assert.Equal(t, expectedOutcome, *result.Outcome)
	require.NotNil(t, result.TestID)
	assert.Equal(t, expectedTestID, *result.TestID)

	if expectedReason != nil {
		require.NotNil(t, result.OutcomeReason)
		assert.Equal(t, *expectedReason, *result.OutcomeReason)
	} else {
		assert.Nil(t, result.OutcomeReason)
	}

	if expectedErrors != nil {
		require.NotNil(t, result.Errors)
		assert.Equal(t, *expectedErrors, *result.Errors)
	} else {
		assert.Nil(t, result.Errors)
	}

	if expectedWarnings != nil {
		require.NotNil(t, result.Warnings)
		assert.Equal(t, *expectedWarnings, *result.Warnings)
	} else {
		assert.Nil(t, result.Warnings)
	}
}
