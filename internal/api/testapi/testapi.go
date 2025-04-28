package testapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Config struct {
	PollInterval time.Duration
	APIVersion   string
}

type client struct {
	lowLevelClient ClientWithResponsesInterface
	config         Config
}

// TestHandle allows for starting a test and waiting on its response
type TestHandle interface {
	Wait(ctx context.Context) (FinalStatus, error)
	Done() <-chan struct{}
	Result() (FinalStatus, error)
}

type testHandle struct {
	client *client
	orgID  uuid.UUID
	jobID  uuid.UUID

	runOnce     sync.Once
	doneChan    chan struct{}
	mu          sync.Mutex // protects finalStatus and err
	finalStatus FinalStatus
	err         error

	// final test ID once discovered during polling
	finalTestID *uuid.UUID
}

type TestClient interface {
	StartTest(ctx context.Context, params StartTestParams) (TestHandle, error)
}

// Return a new instance of the test client.
func NewTestClient(serverBaseUrl string, cfg Config, opts ...ClientOption) (TestClient, error) {
	llClient, err := NewClientWithResponses(serverBaseUrl, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}

	if cfg.APIVersion == "" {
		cfg.APIVersion = "2024-10-15"
	}

	return &client{
		lowLevelClient: llClient,
		config:         cfg}, nil
}

// Create the initial test and return a handle to poll it
func (c *client) StartTest(ctx context.Context, params StartTestParams) (TestHandle, error) {
	// Validate params
	if len(params.Subject.union) == 0 {
		return nil, fmt.Errorf("subject is required in StartTestParams and must be populated")
	}
	if params.OrgID == "" {
		return nil, fmt.Errorf("OrgID is required")
	}
	orgUUID, err := uuid.Parse(params.OrgID)
	if err != nil {
		return nil, fmt.Errorf("invalid OrgID format: %w", err)
	}

	// Create test body
	testAttributes := TestAttributesCreate{Subject: params.Subject}
	requestBody := TestRequestBody{
		Data: TestDataCreate{
			Attributes: testAttributes,
			Type:       TestDataCreateTypeTests, // Set the type for the TestData
		},
	}

	// Prepare parameters for the low-level client call
	createTestParams := &CreateTestParams{Version: c.config.APIVersion}

	// Call the low-level client method
	resp, err := c.lowLevelClient.CreateTestWithApplicationVndAPIPlusJSONBodyWithResponse(
		ctx,
		orgUUID,          // Use parsed OrgID UUID
		createTestParams, // Pass the parameters
		requestBody,      // Pass the constructed request body
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send create test request: %w", err)
	}

	// Handle the response
	if resp.StatusCode() != http.StatusAccepted {
		errorBody := resp.Body
		errMsg := fmt.Sprintf("unexpected status code %d when starting test", resp.StatusCode())
		if resp.ApplicationvndApiJSON400 != nil && len(resp.ApplicationvndApiJSON400.Errors) > 0 {
			// Use the structured error if available
			errMsg = fmt.Sprintf("%s: %s", errMsg, resp.ApplicationvndApiJSON400.Errors[0].Detail)
		} else if len(errorBody) > 0 {
			// Fallback to raw body
			errMsg = fmt.Sprintf("%s, response: %s", errMsg, string(errorBody))
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Extract and return the Job ID from the 202 Accepted response
	if resp.ApplicationvndApiJSON202 == nil {
		return nil, fmt.Errorf("received status %d but response body is unexpectedly nil", resp.StatusCode())
	}

	jobID := resp.ApplicationvndApiJSON202.Data.Id
	if jobID == uuid.Nil {
		return nil, fmt.Errorf("received status %d but job ID in response is nil", resp.StatusCode())
	}

	// Create and return the test handle
	handle := &testHandle{
		client:   c,
		orgID:    orgUUID,
		jobID:    jobID,
		doneChan: make(chan struct{}),
	}

	return handle, nil
}

// Poll the test to completion and return its status
func (h *testHandle) Wait(ctx context.Context) (FinalStatus, error) {
	h.runOnce.Do(func() {
		defer close(h.doneChan)

		finalTestID, err := h.pollJobToCompletion(ctx)
		if err != nil {
			h.setError(fmt.Errorf("polling job %s failed: %w", h.jobID, err))
			return
		}
		h.finalTestID = finalTestID

		finalStatus, err := h.fetchFinalTestStatus(ctx, *finalTestID)
		if err != nil {
			h.setError(fmt.Errorf("failed to fetch final test status for %s: %w", *finalTestID, err))
			return
		}

		h.setResult(finalStatus, nil)
	})

	// Wait until the polling goroutine (started by runOnce.Do) finishes.
	<-h.doneChan
	return h.Result()
}

// Check status of a 200 OK response from GetJob.
// Returns true if polling should stop due to the job itself erroring,
// and an error if the job has errored. Otherwise, it returns false, nil.
func handleJobInProgress(resp *GetJobResponse, jobID uuid.UUID) (stopPolling bool, err error) {
	if resp.ApplicationvndApiJSON200 != nil {
		status := resp.ApplicationvndApiJSON200.Data.Attributes.Status
		if status == Errored {
			return true, fmt.Errorf("job %s reported status 'errored'", jobID)
		}
	}
	return false, nil
}

// Process a 303 See Other response from GetJob.
// Extract the final Test ID from the 'related' link.
// Return testID on success, or an error if parsing fails.
func handleJobRedirect(resp *GetJobResponse, jobID uuid.UUID) (*uuid.UUID, error) {
	if resp.ApplicationvndApiJSON303 == nil {
		return nil, fmt.Errorf("job %s returned 303 but response body was nil", jobID)
	}
	if resp.ApplicationvndApiJSON303.Links.Related == nil {
		return nil, fmt.Errorf("job %s completed (303) but response missing 'links.related'", jobID)
	}

	// Extract the Test ID from the related link
	relLink, err := resp.ApplicationvndApiJSON303.Links.Related.AsIoSnykApiCommonLinkString()
	if err != nil {
		// Try as LinkObject as a fallback
		linkObj, errObj := resp.ApplicationvndApiJSON303.Links.Related.AsIoSnykApiCommonLinkObject()
		if errObj != nil {
			return nil, fmt.Errorf("job %s completed (303) but failed to parse 'links.related' as string or object: %w / %w", jobID, err, errObj)
		}
		relLink = linkObj.Href
	}

	testID, err := extractTestIDFromLink(relLink)
	if err != nil {
		return nil, fmt.Errorf("job %s completed (303) but failed to extract test ID from related link '%s': %w", jobID, relLink, err)
	}
	return testID, nil
}

// Create a detailed error message for unexpected HTTP statuses during polling.
func formatUnexpectedJobStatusError(resp *GetJobResponse, jobID uuid.UUID) error {
	errorBodyBytes := resp.Body
	errMsg := fmt.Sprintf("unexpected status code %d polling job %s", resp.StatusCode(), jobID)
	// Attempt to get more detail from structured error response
	if resp.ApplicationvndApiJSON400 != nil && len(resp.ApplicationvndApiJSON400.Errors) > 0 {
		errMsg = fmt.Sprintf("%s: %s", errMsg, resp.ApplicationvndApiJSON400.Errors[0].Detail)
	} else if len(errorBodyBytes) > 0 {
		// Fallback to raw body if no structured error
		errMsg = fmt.Sprintf("%s, response: %s", errMsg, string(errorBodyBytes))
	}
	return fmt.Errorf("%s", errMsg)
}

// Query the job endpoint until we're redirected to its 'related' link containing results
func (h *testHandle) pollJobToCompletion(ctx context.Context) (*uuid.UUID, error) {
	ticker := time.NewTicker(h.client.config.PollInterval)
	defer ticker.Stop()

	getJobParams := &GetJobParams{Version: h.client.config.APIVersion}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled while polling job %s: %w", h.jobID, ctx.Err())
		case <-ticker.C:
			resp, err := h.client.lowLevelClient.GetJobWithResponse(ctx, h.orgID, h.jobID, getJobParams)
			if err != nil {
				// Consider whether network errors should be retried
				return nil, fmt.Errorf("polling job %s request failed: %w", h.jobID, err)
			}

			switch resp.StatusCode() {
			case http.StatusOK:
				stopPolling, jobErr := handleJobInProgress(resp, h.jobID)
				if stopPolling {
					return nil, jobErr
				}
				continue

			case http.StatusSeeOther:
				// Job finished, redirecting to Test resource
				testID, redirectErr := handleJobRedirect(resp, h.jobID)
				if redirectErr != nil {
					return nil, redirectErr
				}
				return testID, nil

			case http.StatusNotFound:
				// Can happen due to eventual consistency; log and continue polling
				// TODO what is our preferred logging mechanism?
				continue

			default:
				// Unexpected status code
				return nil, formatUnexpectedJobStatusError(resp, h.jobID)
			}
		}
	}
}

// Get the test result outcome from polling and populate FinalStatus.
// Errors returned here are for the API interaction (e.g., bad response), not the test itself.
// Test state is captured in FinalStatus.State and FinalStatus.Message.
func (h *testHandle) fetchFinalTestStatus(ctx context.Context, testID uuid.UUID) (FinalStatus, error) {
	getTestParams := &GetTestParams{Version: h.client.config.APIVersion}
	resp, err := h.client.lowLevelClient.GetTestWithResponse(ctx, h.orgID, testID, getTestParams)
	if err != nil {
		return FinalStatus{}, fmt.Errorf("get test %s request failed: %w", testID, err)
	}

	if resp.StatusCode() != http.StatusOK {
		errorBodyBytes := resp.Body
		errMsg := fmt.Sprintf("unexpected status code %d fetching test %s", resp.StatusCode(), testID)
		if resp.ApplicationvndApiJSON400 != nil && len(resp.ApplicationvndApiJSON400.Errors) > 0 {
			errMsg = fmt.Sprintf("%s: %s", errMsg, resp.ApplicationvndApiJSON400.Errors[0].Detail)
		} else if len(errorBodyBytes) > 0 {
			errMsg = fmt.Sprintf("%s, response: %s", errMsg, string(errorBodyBytes))
		}
		return FinalStatus{}, fmt.Errorf("%s", errMsg)
	}

	if resp.ApplicationvndApiJSON200 == nil {
		return FinalStatus{}, fmt.Errorf("received 200 OK for test %s but response body was nil", testID)
	}

	testData := resp.ApplicationvndApiJSON200.Data
	attrs := testData.Attributes
	status := FinalStatus{
		TestID:           testData.Id,
		EffectiveSummary: attrs.EffectiveSummary,
		RawSummary:       attrs.RawSummary,
	}

	if attrs.State != nil {
		status.State = string(attrs.State.Execution)
		if len(*attrs.State.Errors) > 0 {
			// Aggregate error messages
			var errorMessages []string
			for _, apiError := range *attrs.State.Errors {
				errorMessages = append(errorMessages, apiError.Detail)
			}
			status.Message = strings.Join(errorMessages, "; ")
		}
	} else {
		status.State = "unknown" // Should not happen if test completed, but defensive
	}

	if attrs.Outcome != nil {
		status.Outcome = &attrs.Outcome.Result
		status.OutcomeReason = attrs.Outcome.Reason
	}

	return status, nil
}

// Returns a test UUID from a test link such as "/orgs/{org_id}/tests/{test_id}?version=..."
func extractTestIDFromLink(link string) (*uuid.UUID, error) {
	parsedURL, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL '%s': %w", link, err)
	}
	path := parsedURL.Path

	// Expected structure: "", "orgs", "uuid1", "tests", "uuid2"
	parts := strings.Split(path, "/")

	for i, part := range parts {
		if part == "tests" && i+1 < len(parts) {
			uuidStr := parts[i+1]
			uuid, err := uuid.Parse(uuidStr)
			if err != nil {
				return nil, fmt.Errorf("failed to extract test UUID: %w", err)
			}

			return &uuid, nil
		}
	}
	return nil, fmt.Errorf("pattern '/tests/<uuid>' not found in '%s'", path)
}

// StartTestParams defines parameters for the high-level StartTest function.
type StartTestParams struct {
	OrgID   string
	Subject TestSubjectCreate
}

// High-level results and status of a completed test.
type FinalStatus struct {
	State   string // e.g., "finished", "errored"
	Message string // Optional status message or error details

	// Fields available after completion via GetTest:
	TestID           *uuid.UUID         // The final Test ID (different from Job ID)
	Outcome          *PassFail          // Pass or Fail
	OutcomeReason    *TestOutcomeReason // Reason for the outcome (e.g., policy_breach)
	EffectiveSummary *FindingSummary    // Summary excluding suppressed findings
	RawSummary       *FindingSummary    // Summary including suppressed findings
}

// Returns a channel signaling completion of Wait()
func (h *testHandle) Done() <-chan struct{} { return h.doneChan }

func (h *testHandle) Result() (FinalStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.finalStatus, h.err
}
func (h *testHandle) setResult(status FinalStatus, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.finalStatus = status
	h.err = err
}
func (h *testHandle) setError(err error) { h.setResult(FinalStatus{}, err) }
