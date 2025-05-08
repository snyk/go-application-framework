package testapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	// Create a DepGraph test
	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Define expected request body that StartTest should generate
	expectedRequestBody := testapi.TestRequestBody{
		Data: testapi.TestDataCreate{
			Attributes: testapi.TestAttributesCreate{Subject: params.Subject},
			Type:       testapi.TestDataCreateTypeTests,
		},
	}

	handler := newPassingTestServerHandler(t, orgID, expectedJobID, finalTestID, apiVersion, expectedRequestBody, &pollCounter)

	// Act
	clientConfig := testapi.Config{
		APIVersion:   apiVersion,
		PollInterval: 10 * time.Millisecond, // Use a short poll interval for faster tests
	}
	testClient, cleanup := startMockServerAndClientWithConfig(t, clientConfig, handler)
	defer cleanup()

	handle, err := testClient.StartTest(ctx, params)

	// Assert
	assert.NoError(t, err, "StartTest returned an unexpected error")
	assert.NotNil(t, handle, "StartTest returned a nil handle")

	// No result yet before Wait
	initialResult, err := handle.Result()
	assert.NoError(t, err)
	assert.Equal(t, testapi.FinalStatus{}, initialResult)

	// Now wait for test to complete
	finalStatus, err := handle.Wait(ctx)

	// Assert final status after Wait()
	assert.NoError(t, err, "Wait returned an unexpected error")
	assert.Equal(t, string(testapi.Finished), finalStatus.State)
	require.NotNil(t, finalStatus.Outcome, "Outcome should not be nil")
	assert.Equal(t, testapi.Pass, *finalStatus.Outcome)
	require.NotNil(t, finalStatus.TestID, "TestID should not be nil")
	assert.Equal(t, finalTestID, *finalStatus.TestID) // Ensure the handler-generated TestID is in the status
	assert.Nil(t, finalStatus.OutcomeReason, "OutcomeReason should be nil for Pass")
	assert.Empty(t, finalStatus.Message, "Message should be empty for success")
	assert.GreaterOrEqual(t, pollCounter.Load(), int32(2), "Should have polled at least twice for the job status")

	// Wait->finalStatus and Result() are the synchronous and async ways of getting the same output so they should should match.
	resultAfterWait, err := handle.Result()
	assert.NoError(t, err)
	assert.Equal(t, finalStatus, resultAfterWait)
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

	// Act: error occurs before network so client can point nowhere
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

	// Error response body from mock server
	errorCode := "SNYK-TEST-4001"
	errorResponse := testapi.IoSnykApiCommonErrorDocument{
		Jsonapi: testapi.IoSnykApiCommonJsonApi{Version: testapi.N10},
		Errors: []testapi.IoSnykApiCommonError{
			{Detail: "Invalid subject provided", Status: "400", Code: &errorCode},
		},
	}
	errorBodyBytes, err := json.Marshal(errorResponse)
	require.NoError(t, err, "Failed to marshal error response body")

	// Create the httptest server to return 400 Bad Request

	handler := func(w http.ResponseWriter, r *http.Request) {
		expectedPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		if r.URL.Path != expectedPath || r.Method != http.MethodPost {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusBadRequest) // 400 Bad Request
		_, writeErr := w.Write(errorBodyBytes)
		assert.NoError(t, writeErr)
	}
	testClient, cleanup := startMockServerAndClient(t, handler)
	defer cleanup()

	// Act
	testSubject := newDepGraphTestSubject(t, uuid.New())
	params := testapi.StartTestParams{OrgID: orgID.String(), Subject: testSubject}

	handle, err := testClient.StartTest(ctx, params)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "unexpected status code 400")
	assert.Contains(t, err.Error(), "Invalid subject provided")
}

// Calling StartTest with an non-listening server returns an error
func Test_StartTest_Error_Network(t *testing.T) {
	// Arrange
	t.Parallel()

	// Use a short timeout to ensure test doesn't hang
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	orgID := uuid.New()
	apiVersion := "2024-10-15"

	// Point to a non-listening port
	clientConfig := testapi.Config{APIVersion: apiVersion}
	testClient, err := testapi.NewTestClient("http://127.0.0.1:1", clientConfig)
	require.NoError(t, err)

	// Act
	testSubject := newDepGraphTestSubject(t, uuid.New())
	params := testapi.StartTestParams{OrgID: orgID.String(), Subject: testSubject}

	handle, err := testClient.StartTest(ctx, params)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, handle)

	assert.True(t, strings.Contains(err.Error(), "failed to send create test request") ||
		strings.Contains(err.Error(), "context deadline exceeded") ||
		strings.Contains(err.Error(), "connection refused"),
		"Error message should indicate network failure or timeout: %v", err)
}

// Synchronous Wait() - start a test, wait for 303 redirect, and check for "Pass" outcome.
// The TestClient uses the default config.
func Test_Wait_Synchronous_Success_Pass(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	apiVersion := "2024-10-15"
	var pollCount atomic.Int32

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Define expected request body that StartTest should generate
	expectedRequestBody := testapi.TestRequestBody{
		Data: testapi.TestDataCreate{
			Attributes: testapi.TestAttributesCreate{Subject: params.Subject},
			Type:       testapi.TestDataCreateTypeTests,
		},
	}

	handler := newPassingTestServerHandler(t, orgID, jobID, testID, apiVersion, expectedRequestBody, &pollCount)

	// Act
	testClient, cleanup := startMockServerAndClient(t, handler)
	defer cleanup()

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	finalStatus, err := handle.Wait(ctx)

	// Assert - state: Finished, outcome: Pass
	assert.NoError(t, err, "Wait returned an unexpected error")
	assert.Equal(t, string(testapi.Finished), finalStatus.State) // State comes from TestState.Execution
	require.NotNil(t, finalStatus.Outcome, "Outcome should not be nil")
	assert.Equal(t, testapi.Pass, *finalStatus.Outcome)
	require.NotNil(t, finalStatus.TestID, "TestID should not be nil")
	assert.Equal(t, testID, *finalStatus.TestID)
	assert.Nil(t, finalStatus.OutcomeReason, "OutcomeReason should be nil for Pass")
	assert.Empty(t, finalStatus.Message, "Message should be empty for success")
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2), "Should have polled at least twice")
}

// Synchronous Wait() - start a test, wait for 303 redirect, check for "Pass" outcome,
// then fetch findings using the low-level client.  There is 1 finding with Severity High.
// TODO Switch to the high-level client when findings are available.
func Test_Wait_Synchronous_Success_Pass_WithFindings(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	testID := uuid.New()
	apiVersion := "2024-10-15"
	pollCount := int32(0)
	var findingsEndpointCalled atomic.Bool

	testSubject := newDepGraphTestSubject(t, assetID)
	startParams := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", orgID, jobID)
		expectedResultPath := fmt.Sprintf("/orgs/%s/tests/%s", orgID, testID)
		expectedFindingsPath := fmt.Sprintf("/orgs/%s/tests/%s/findings", orgID, testID)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			startResp := mockStartTestResponse(t, jobID)
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write(startResp)
			assert.NoError(t, err, "failed to write create response")

		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			count := atomic.AddInt32(&pollCount, 1)
			if count == 1 {
				jobResp := mockJobStatusResponse(t, jobID, testapi.Pending)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job response")
			} else {
				relatedLink := fmt.Sprintf("%s%s", serverURLFromRequest(r), expectedResultPath)
				jobResp := mockJobRedirectResponse(t, jobID, relatedLink)
				w.Header().Set("Location", relatedLink)
				w.WriteHeader(http.StatusSeeOther)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job redirect response")
			}

		case r.Method == http.MethodGet && r.URL.Path == expectedResultPath:
			resultResp := mockTestResultResponse(t, testID, testapi.Pass, nil)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(resultResp)
			assert.NoError(t, err, "failed to write result response")

		case r.Method == http.MethodGet && r.URL.Path == expectedFindingsPath:
			// Verify findings request parameters
			assert.Equal(t, apiVersion, r.URL.Query().Get("version"))
			assert.Equal(t, "10", r.URL.Query().Get("limit")) // Example limit check

			findingsEndpointCalled.Store(true) // Mark that this handler was called

			// Respond with mock findings
			findingsResp := mockListFindingsResponse(t)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(findingsResp)
			assert.NoError(t, err, "failed to write findings response")

		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}

	// Act
	// Create both high-level and low-level clients pointing to the same mock server
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	baseClient := server.Client()
	testHTTPClient := &http.Client{
		Transport: baseClient.Transport,
		Timeout:   baseClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	clientConfig := testapi.Config{
		APIVersion:   apiVersion,
		PollInterval: 10 * time.Millisecond,
	}
	hlClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err, "Failed to create high-level test client")

	lowLevelClient, err := testapi.NewClientWithResponses(server.URL, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err, "Failed to create low-level client with responses")

	// Start the test using the high-level client
	handle, err := hlClient.StartTest(ctx, startParams)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Wait for the test to complete
	finalStatus, waitErr := handle.Wait(ctx) // Rename inner err to waitErr

	// Assert initial test completion (Pass)
	assert.NoError(t, waitErr, "Wait returned an unexpected error") // Use waitErr
	assert.Equal(t, string(testapi.Finished), finalStatus.State)
	require.NotNil(t, finalStatus.Outcome, "Outcome should not be nil")
	assert.Equal(t, testapi.Pass, *finalStatus.Outcome)
	require.NotNil(t, finalStatus.TestID, "TestID should not be nil")
	assert.Equal(t, testID, *finalStatus.TestID)
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(2), "Should have polled at least twice")

	// Fetch findings using the low-level client
	var findingsResp *testapi.ListFindingsResponse
	findingsParams := &testapi.ListFindingsParams{
		Version: apiVersion,
		Limit:   ptr(int8(10)), // Example limit
	}
	findingsResp, findingsErr := lowLevelClient.ListFindingsWithResponse(ctx, orgID, *finalStatus.TestID, findingsParams) // Use different var name

	// Assert findings fetch
	assert.NoError(t, findingsErr, "ListFindingsWithResponse returned an error")
	require.NotNil(t, findingsResp, "Findings response should not be nil")
	assert.Equal(t, http.StatusOK, findingsResp.StatusCode(), "Expected 200 OK for findings")
	assert.NotNil(t, findingsResp.ApplicationvndApiJSON200, "Findings response body should not be nil")
	assert.True(t, findingsEndpointCalled.Load(), "Mock findings endpoint handler was not called")

	if findingsResp.ApplicationvndApiJSON200 != nil {
		assert.Len(t, findingsResp.ApplicationvndApiJSON200.Data, 1, "Expected 1 mock finding")
		if len(findingsResp.ApplicationvndApiJSON200.Data) > 0 {
			finding := findingsResp.ApplicationvndApiJSON200.Data[0]
			assert.Equal(t, testapi.Findings, *finding.Type)
			assert.Equal(t, "XYZ High Sev", finding.Attributes.Title)
			assert.Equal(t, testapi.SeverityHigh, finding.Attributes.Rating.Severity)
			assert.Equal(t, uint16(80), finding.Attributes.Risk.RiskScore.Value)
		}
	}
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
	pollCount := int32(0)
	failReason := testapi.TestOutcomeReasonPolicyBreach

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", orgID, jobID)
		expectedResultPath := fmt.Sprintf("/orgs/%s/tests/%s", orgID, testID)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			startResp := mockStartTestResponse(t, jobID)
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write(startResp)
			assert.NoError(t, err, "failed to write create response")

		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			count := atomic.AddInt32(&pollCount, 1)
			if count == 1 {
				jobResp := mockJobStatusResponse(t, jobID, testapi.Pending)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job response")
			} else {
				relatedLink := fmt.Sprintf("%s%s", serverURLFromRequest(r), expectedResultPath)
				jobResp := mockJobRedirectResponse(t, jobID, relatedLink)
				w.Header().Set("Location", relatedLink)
				w.WriteHeader(http.StatusSeeOther)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job redirect response")
			}

		case r.Method == http.MethodGet && r.URL.Path == expectedResultPath:
			// Final result is Fail with a reason
			resultResp := mockTestResultResponse(t, testID, testapi.Fail, &failReason)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(resultResp)
			assert.NoError(t, err, "failed to write result response")

		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}

	// Act
	testClient, cleanup := startMockServerAndClient(t, handler)
	defer cleanup()

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	finalStatus, err := handle.Wait(ctx)

	// Assert - state: Finished, outcome: Failed and with failReason
	assert.NoError(t, err, "Wait returned an unexpected error")
	assert.Equal(t, string(testapi.Finished), finalStatus.State)
	require.NotNil(t, finalStatus.Outcome, "Outcome should not be nil")
	assert.Equal(t, testapi.Fail, *finalStatus.Outcome)
	require.NotNil(t, finalStatus.TestID, "TestID should not be nil")
	assert.Equal(t, testID, *finalStatus.TestID)
	require.NotNil(t, finalStatus.OutcomeReason, "OutcomeReason should not be nil")
	assert.Equal(t, failReason, *finalStatus.OutcomeReason)
	assert.Empty(t, finalStatus.Message, "Message should be empty for success")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(2), "Should have polled at least twice")
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
			Type:       testapi.TestDataCreateTypeTests,
		},
	}

	// Act
	handler := newPassingTestServerHandler(t, orgID, jobID, testID, apiVersion, expectedRequestBody, &pollCount)
	testClient, cleanup := startMockServerAndClient(t, handler)
	defer cleanup()

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	go func() {
		// the error here is checked via Result()
		_, waitErr := handle.Wait(ctx)
		assert.NoError(t, waitErr)
	}()

	var finalStatus testapi.FinalStatus
	select {
	case <-handle.Done():
		finalStatus, err = handle.Result()
		assert.NoError(t, err, "Result() returned an unexpected error after Done()")
	case <-time.After(5 * time.Second): // Generous timeout for test
		t.Fatal("Timed out waiting for handle.Done()")
	}

	// Assert - state: Finished, outcome: Pass
	assert.Equal(t, string(testapi.Finished), finalStatus.State)
	require.NotNil(t, finalStatus.Outcome, "Outcome should not be nil")
	assert.Equal(t, testapi.Pass, *finalStatus.Outcome)
	require.NotNil(t, finalStatus.TestID, "TestID should not be nil")
	assert.Equal(t, testID, *finalStatus.TestID)
	assert.Nil(t, finalStatus.OutcomeReason, "OutcomeReason should be nil for Pass")
	assert.Empty(t, finalStatus.Message, "Message should be empty for success")
	assert.GreaterOrEqual(t, pollCount.Load(), int32(2), "Should have polled at least twice")
}

// Test that synchronous Wait() returns an error from the second GET job request.
func Test_Wait_Synchronous_JobErrored(t *testing.T) {
	// Arrange
	t.Parallel()
	ctx := context.Background()
	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	pollCount := int32(0)
	// Note: The job resource itself doesn't have a message field.
	// The error comes from the Wait() function detecting the 'errored' status.

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", orgID, jobID)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			startResp := mockStartTestResponse(t, jobID)
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write(startResp)
			assert.NoError(t, err, "failed to write create response")

		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			count := atomic.AddInt32(&pollCount, 1)
			if count == 1 {
				jobResp := mockJobStatusResponse(t, jobID, testapi.Pending)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job response")
			} else {
				// Second poll: Errored
				jobResp := mockJobStatusResponse(t, jobID, testapi.Errored)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job redirect response")
			}

		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}

	// Act
	testClient, cleanup := startMockServerAndClient(t, handler)
	defer cleanup()

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	finalStatus, err := handle.Wait(ctx)

	// Assert
	assert.Error(t, err, "Wait should return an error when the job status is 'errored'")
	assert.Contains(t, err.Error(), fmt.Sprintf("job %s reported status 'errored'", jobID), "Error message should indicate job errored")
	assert.Contains(t, err.Error(), fmt.Sprintf("polling job %s failed", jobID), "Error message should indicate polling failed")
	assert.Equal(t, testapi.FinalStatus{}, finalStatus, "FinalStatus should be zero value on polling error")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(2), "Should have polled at least twice")
}

// Test asynchronous Wait() when polling times out due to context cancellation.
// Polling is every 10ms. The Wait context times out at 100ms, before the request responds at 150ms.
func Test_Wait_Asynchronous_PollingTimeout(t *testing.T) {
	// Arrange
	t.Parallel()
	// Short context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	orgID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	apiVersion := "2024-10-15"
	pollCount := int32(0)

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler - always returns pending
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", orgID, jobID)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			startResp := mockStartTestResponse(t, jobID)
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write(startResp)
			assert.NoError(t, err, "failed to write create response")

		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			atomic.AddInt32(&pollCount, 1)
			// Simulate delay longer than context timeout to ensure cancellation happens during wait
			time.Sleep(250 * time.Millisecond)
			jobResp := mockJobStatusResponse(t, jobID, testapi.Pending)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(jobResp)
			assert.NoError(t, err, "failed to write job response")

		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}

	// Act
	// Use a client config with a very short poll interval for the test
	clientConfig := testapi.Config{APIVersion: apiVersion, PollInterval: 10 * time.Millisecond}
	testClient, cleanup := startMockServerAndClientWithConfig(t, clientConfig, handler)
	defer cleanup()

	// StartTest is on a background context so it's not affected by ctx's short timeout
	handle, err := testClient.StartTest(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	go func() {
		// Use the timeout context for Wait
		_, err = handle.Wait(ctx)
		assert.Error(t, err)
	}()

	var finalStatus testapi.FinalStatus
	var waitErr error
	select {
	case <-handle.Done():
		finalStatus, waitErr = handle.Result()
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for handle.Done() (expected context cancellation)")
	}

	// Assert - Wait returns an error; timeout occurs while it waits on the HTTP response
	assert.Error(t, waitErr, "Wait should have returned an error due to context timeout")
	assert.ErrorIs(t, waitErr, context.DeadlineExceeded, "Error should be DeadlineExceeded")
	assert.Contains(t, waitErr.Error(), "context deadline exceeded", "Error message should indicate timeout")
	assert.Equal(t, testapi.FinalStatus{}, finalStatus, "FinalStatus should be zero value on timeout error")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(1), "Should have polled at least once before timeout")
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
	pollCount := int32(0)

	testSubject := newDepGraphTestSubject(t, assetID)
	params := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: testSubject,
	}

	// Mock server handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", orgID, jobID)
		expectedResultPath := fmt.Sprintf("/orgs/%s/tests/%s", orgID, testID)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			startResp := mockStartTestResponse(t, jobID)
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write(startResp)
			assert.NoError(t, err, "failed to write create response")

		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			count := atomic.AddInt32(&pollCount, 1)
			if count == 1 {
				jobResp := mockJobStatusResponse(t, jobID, testapi.Pending)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job response")
			} else {
				// Redirect (303) to final result
				relatedLink := fmt.Sprintf("%s%s", serverURLFromRequest(r), expectedResultPath)
				jobResp := mockJobRedirectResponse(t, jobID, relatedLink)
				w.Header().Set("Location", relatedLink)
				w.WriteHeader(http.StatusSeeOther)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write job redirect response")
			}

		case r.Method == http.MethodGet && r.URL.Path == expectedResultPath:
			// Fetching the final test result fails with 404
			http.Error(w, "Test Result Not Found", http.StatusNotFound)

		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}

	// Act
	testClient, cleanup := startMockServerAndClient(t, handler)
	defer cleanup()

	handle, err := testClient.StartTest(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, handle)

	finalStatus, err := handle.Wait(ctx)

	// Assert - Wait returns an error
	assert.Error(t, err, "Wait should return an error when fetching result fails")
	assert.Contains(t, err.Error(), "failed to fetch final test status", "Error message should indicate result fetch failure")
	assert.Contains(t, err.Error(), "unexpected status code 404", "Error message should mention the status code")
	assert.Equal(t, testapi.FinalStatus{}, finalStatus, "FinalStatus should be zero value on error")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(2), "Should have polled at least twice")
}

// --- support functions ---

// newMockFullPassWorkflowHandler creates an http.HandlerFunc that simulates a complete
// successful test workflow:
// 1. POST /tests -> 202 Accepted (returns jobIDToReturn)
// 2. GET /test_jobs/{jobIDToReturn} (poll 1) -> 200 OK (status Pending)
// 3. GET /test_jobs/{jobIDToReturn} (poll 2) -> 303 See Other (redirects to /tests/{testIDToReturn})
// 4. GET /tests/{testIDToReturn} -> 200 OK (final status Pass)
// It also asserts the request body of the initial Create Test POST to /tests.
func newPassingTestServerHandler(
	t *testing.T,
	orgID, jobIDToReturn, testIDToReturn uuid.UUID,
	apiVersion string,
	expectedCreateTestBody testapi.TestRequestBody,
	pollCounter *atomic.Int32,
) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", orgID, jobIDToReturn)
		expectedResultPath := fmt.Sprintf("/orgs/%s/tests/%s", orgID, testIDToReturn)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			assert.Equal(t, apiVersion, r.URL.Query().Get("version"))
			assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

			bodyBytes, bodyErr := io.ReadAll(r.Body)
			require.NoError(t, bodyErr)
			defer r.Body.Close()
			expectedBodyBytes, err := json.Marshal(expectedCreateTestBody)
			require.NoError(t, err, "failed to marshal expected request body: %v", err)
			assert.JSONEq(t, string(expectedBodyBytes), string(bodyBytes))

			startResp := mockStartTestResponse(t, jobIDToReturn)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write(startResp)
			assert.NoError(t, err, "failed to write start test response")
		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			count := pollCounter.Add(1)
			if count == 1 { // First poll: Pending
				jobResp := mockJobStatusResponse(t, jobIDToReturn, testapi.Pending)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write pending job response")
			} else { // Subsequent polls: Redirect to final result
				relatedLink := fmt.Sprintf("%s%s", serverURLFromRequest(r), expectedResultPath)
				jobResp := mockJobRedirectResponse(t, jobIDToReturn, relatedLink)
				w.Header().Set("Location", relatedLink)
				w.WriteHeader(http.StatusSeeOther)
				_, err := w.Write(jobResp)
				assert.NoError(t, err, "failed to write redirect job response")
			}
		case r.Method == http.MethodGet && r.URL.Path == expectedResultPath:
			resultResp := mockTestResultResponse(t, testIDToReturn, testapi.Pass, nil)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(resultResp)
			assert.NoError(t, err, "failed to write final test result response")
		default:
			http.Error(w, fmt.Sprintf("Mock server: Unexpected request: %s %s", r.Method, r.URL.Path), http.StatusNotFound)
		}
	}
}

// Parses a sample JSON string and returns the depGraph part.
// Fails the test immediately if unmarshalling fails.
func depGraphFromJSON(t *testing.T) testapi.IoSnykApiV1testdepgraphRequestDepGraph {
	t.Helper()

	jsonImport := `
		{
			"displayTargetFile": "package.json",
			"foundProjectCount": 1,
			"targetFileRelativePath": "/path/to/project/package.json",
			"depGraph": {
				"schemaVersion": "1.3.0",
				"pkgManager": {
					"name": "npm"
				},
				"pkgs": [
					{
						"id": "root-pkg@1.0.0",
						"info": {
							"name": "root-pkg",
							"version": "1.0.0"
						}
					} 
				],
				"graph": {
					"rootNodeId": "root-node",
					"nodes": [
						{
							"nodeId": "root-node",
							"pkgId": "root-pkg@1.0.0",
							"deps": []
						}
					]
				}
			}
		}
	`

	var topLevelStruct struct {
		DepGraph testapi.IoSnykApiV1testdepgraphRequestDepGraph `json:"depGraph"`
	}
	err := json.Unmarshal([]byte(jsonImport), &topLevelStruct)
	require.NoError(t, err, "unmarshaling depGraph from JSON failed")

	return topLevelStruct.DepGraph
}

// Return a depGraph to run a test on
func newDepGraphTestSubject(t *testing.T, assetID openapi_types.UUID) testapi.TestSubjectCreate {
	t.Helper()
	testSubject := testapi.TestSubjectCreate{}
	err := testSubject.FromDepGraphSubjectCreate(testapi.DepGraphSubjectCreate{
		Type:        testapi.DepGraphSubjectCreateTypeDepGraph,
		AssetId:     assetID,
		DepGraph:    depGraphFromJSON(t),
		SourceFiles: []string{"package.json"},
	})
	require.NoError(t, err, "Failed to create dep-graph test subject")
	return testSubject
}

// Sets up an httptest server with the given handler and returns a
// testapi.Client configured to use it, along with a cleanup function.
func startMockServerAndClient(t *testing.T, handler http.HandlerFunc) (testapi.TestClient, func()) {
	t.Helper()
	apiVersion := "2024-10-15"
	clientConfig := testapi.Config{
		APIVersion:   apiVersion,
		PollInterval: 10 * time.Millisecond, // Use short poll interval for tests
	}
	return startMockServerAndClientWithConfig(t, clientConfig, handler)
}

// Sets up an httptest server with the given handler. Accepts a config with test polling interval and API version.
func startMockServerAndClientWithConfig(t *testing.T, clientConfig testapi.Config, handler http.HandlerFunc) (testapi.TestClient, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	cleanup := func() { server.Close() }

	baseClient := server.Client()

	testHTTPClient := &http.Client{
		Transport: baseClient.Transport,
		Timeout:   baseClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	testClient, err := testapi.NewTestClient(server.URL, clientConfig, testapi.WithHTTPClient(testHTTPClient))
	require.NoError(t, err, "Failed to create test client for mock server")
	require.NotNil(t, testClient)

	return testClient, cleanup
}

// serverURLFromRequest extracts the base URL (scheme + host) from an incoming request.
func serverURLFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

// --- Mock Response Builders ---

// Creates a marshaled JSON response for the initial POST /tests call (202 Accepted).
func mockStartTestResponse(t *testing.T, jobID openapi_types.UUID) []byte {
	t.Helper()
	respData := struct {
		Attributes testapi.JobAttributes         `json:"attributes"`
		Id         openapi_types.UUID            `json:"id"`
		Type       testapi.CreateTest202DataType `json:"type"`
	}{
		Attributes: testapi.JobAttributes{
			Status:    testapi.Pending, // Initial status is Pending
			CreatedAt: time.Now(),
		},
		Id:   jobID,
		Type: "test_jobs", // As defined in CreateTestResponse
	}
	mockResponseBody := struct {
		Data    interface{}                    `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
		Links   testapi.CreateTest_202_Links   `json:"links"`
		Meta    *testapi.IoSnykApiCommonMeta   `json:"meta,omitempty"`
	}{
		Data: respData,
		Jsonapi: testapi.IoSnykApiCommonJsonApi{
			Version: testapi.N10,
		},
		Links: testapi.CreateTest_202_Links{}, // No self link needed for this mock
	}
	responseBodyBytes, err := json.Marshal(mockResponseBody)
	require.NoError(t, err, "Failed to marshal mock start test response")
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /test_jobs/{job_id} polling call (200 OK).
func mockJobStatusResponse(t *testing.T, jobID openapi_types.UUID, status testapi.TestExecutionStates) []byte {
	t.Helper()
	attributes := testapi.JobAttributes{
		Status:    status,
		CreatedAt: time.Now().Add(-1 * time.Minute), // Assume created a bit ago
	}

	links := testapi.GetJob_200_Links{}
	responseData := testapi.JobData{
		Attributes: attributes,
		Id:         jobID,
		Type:       testapi.TestJobs,
	}

	mockResponseBody := struct {
		Data    testapi.JobData                `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
		Links   testapi.GetJob_200_Links       `json:"links"`
		Meta    *testapi.IoSnykApiCommonMeta   `json:"meta,omitempty"`
	}{
		Data: responseData,
		Jsonapi: testapi.IoSnykApiCommonJsonApi{
			Version: testapi.N10,
		},
		Links: links,
	}
	responseBodyBytes, err := json.Marshal(mockResponseBody)
	require.NoError(t, err, "Failed to marshal mock job status response")
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /test_jobs/{job_id} redirect call (303 See Other).
func mockJobRedirectResponse(t *testing.T, jobID openapi_types.UUID, relatedLink string) []byte {
	t.Helper()
	// Status is typically 'finished' or similar when redirecting, but the exact status
	// in the 303 response might not be strictly defined or used by the client,
	// as the client primarily cares about the redirect link. Let's use Finished.
	attributes := testapi.JobAttributes{
		Status:    testapi.Finished,
		CreatedAt: time.Now().Add(-1 * time.Minute),
	}

	links := testapi.GetJob_303_Links{}
	var linkProp testapi.IoSnykApiCommonLinkProperty
	err := linkProp.FromIoSnykApiCommonLinkString(relatedLink)
	require.NoError(t, err, "Failed to create link property from string")
	links.Related = &linkProp

	responseData := testapi.JobData{
		Attributes: attributes,
		Id:         jobID,
		Type:       testapi.TestJobs,
	}

	mockResponseBody := struct {
		Data    testapi.JobData                `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
		Links   testapi.GetJob_303_Links       `json:"links"`
		Meta    *testapi.IoSnykApiCommonMeta   `json:"meta,omitempty"`
	}{
		Data: responseData,
		Jsonapi: testapi.IoSnykApiCommonJsonApi{
			Version: testapi.N10,
		},
		Links: links,
	}
	responseBodyBytes, err := json.Marshal(mockResponseBody)
	require.NoError(t, err, "Failed to marshal mock job redirect response")
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /tests/{test_id} call (200 OK).
func mockTestResultResponse(
	t *testing.T,
	testID openapi_types.UUID,
	outcomeResult testapi.PassFail,
	outcomeReason *testapi.TestOutcomeReason,
) []byte {
	t.Helper()
	attributes := testapi.TestAttributes{
		Outcome: &testapi.TestOutcome{
			Result: outcomeResult,
			Reason: outcomeReason,
		},
		State: &testapi.TestState{
			Execution: testapi.Finished,
			Errors:    nil,
		},
		EffectiveSummary: nil,
	}

	responseData := testapi.TestData{
		Attributes: attributes,
		Id:         &testID,
		Type:       testapi.TestDataTypeTests,
	}

	mockResponseBody := struct {
		Data    testapi.TestData               `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
		Links   testapi.GetTest_200_Links      `json:"links"`
		Meta    *testapi.IoSnykApiCommonMeta   `json:"meta,omitempty"`
	}{
		Data: responseData,
		Jsonapi: testapi.IoSnykApiCommonJsonApi{
			Version: testapi.N10,
		},
		Links: testapi.GetTest_200_Links{},
	}
	responseBodyBytes, err := json.Marshal(mockResponseBody)
	require.NoError(t, err, "Failed to marshal mock test result response")
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /tests/{test_id}/findings call (200 OK).
// Uses the anonymous struct within ListFindingsResponse for the 200 response.
func mockListFindingsResponse(t *testing.T) []byte {
	t.Helper()

	findingID := uuid.New()
	findingTypeConst := testapi.FindingTypeSca
	findingKey := "ABCD-FINDING-PROBLEM-HIGH"
	findingTitle := "XYZ High Sev"
	findingDesc := "Finding example high sev"
	cveID := "CVE-2024-12345"
	filePath := "package-lock.json"
	lineNum := int32(42)

	// Create a mock Problem (CVE)
	var problem testapi.Problem
	err := problem.FromCveProblem(testapi.CveProblem{
		Id:     cveID,
		Source: testapi.Cve,
	})
	require.NoError(t, err, "Failed to create mock CVE problem")

	// Create a mock Location (SourceFile)
	var location testapi.FindingLocation
	err = location.FromSourceFileLocation(testapi.SourceFileLocation{
		FilePath: filePath,
		FromLine: lineNum,
		Type:     testapi.SourceFile,
	})
	require.NoError(t, err, "Failed to create mock source file location")

	// Create mock FindingAttributes
	findingAttrs := testapi.FindingAttributes{
		CauseOfFailure: false,
		Description:    findingDesc,
		Evidence:       []testapi.Evidence{},
		FindingType:    findingTypeConst,
		Key:            findingKey,
		Locations:      []testapi.FindingLocation{location},
		Problems:       []testapi.Problem{problem},
		Rating:         testapi.Rating{Severity: testapi.SeverityHigh},
		Risk:           testapi.Risk{RiskScore: &testapi.RiskScore{Value: uint16(80)}},
		Title:          findingTitle,
	}

	// Create mock FindingData
	findingDataTypeVar := testapi.Findings
	findingData := testapi.FindingData{
		Attributes: &findingAttrs,
		Id:         &findingID,
		Type:       &findingDataTypeVar,
	}

	// Instantiate the anonymous struct defined within ListFindingsResponse.ApplicationvndApiJSON200
	mockResponseBody := struct {
		Data    []testapi.FindingData                 `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi        `json:"jsonapi"`
		Links   testapi.IoSnykApiCommonPaginatedLinks `json:"links"`
		Meta    *testapi.IoSnykApiCommonMeta          `json:"meta,omitempty"`
	}{
		Data: []testapi.FindingData{findingData}, // Include the mock finding
		Jsonapi: testapi.IoSnykApiCommonJsonApi{
			Version: testapi.N10,
		},
		Links: testapi.IoSnykApiCommonPaginatedLinks{}, // Empty links for simple mock
	}

	responseBodyBytes, err := json.Marshal(mockResponseBody)
	require.NoError(t, err, "Failed to marshal mock list findings response")
	return responseBodyBytes
}

// ptr returns a pointer to the given value. Useful for optional fields.
func ptr[T any](v T) *T {
	return &v
}
