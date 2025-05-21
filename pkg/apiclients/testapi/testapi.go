package testapi

//go:generate $GOPATH/bin/mockgen -source=testapi.go -destination ../mocks/testapi.go -package mocks -imports testapi=github.com/snyk/go-application-framework/pkg/apiclients/testapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

type Config struct {
	PollInterval time.Duration // Default: 2000ms, Min: 1000ms
	PollTimeout  time.Duration // Max total time for polling. Default: 30 min.
	APIVersion   string
}

// Predefined errors for findings operations
var (
	ErrInvalidStateForFindings = errors.New("cannot fetch findings: test ID or internal handle is missing")
	ErrFindingsFetchCanceled   = errors.New("findings fetch operation was canceled")
	ErrFindingsPageRequest     = errors.New("failed to request a page of findings")
	ErrFindingsPageResponse    = errors.New("unexpected API response when fetching findings page")
	ErrFindingsPageData        = errors.New("invalid data in findings page API response")
	ErrFindingsNextPageCursor  = errors.New("failed to determine next findings page cursor from API response")
)

type client struct {
	lowLevelClient ClientWithResponsesInterface
	config         Config
}

// TestHandle allows for starting a test and waiting on its response
type TestHandle interface {
	Wait(ctx context.Context) error
	Done() <-chan struct{}
	Result() *Result
}

type testHandle struct {
	client *client
	orgID  uuid.UUID
	jobID  uuid.UUID

	runOnce  sync.Once
	doneChan chan struct{}
	mu       sync.Mutex // protects result
	result   *Result

	// final test ID once discovered during polling
	finalTestID *uuid.UUID
}

type TestClient interface {
	StartTest(ctx context.Context, params StartTestParams) (TestHandle, error)
}

const (
	DefaultPollInterval = 2 * time.Second
	MinPollInterval     = 1 * time.Second
	MaxFindingsPerPage  = 100
)

// StartTestParams defines parameters for the high-level StartTest function.
type StartTestParams struct {
	OrgID   string
	Subject TestSubjectCreate
}

// High-level results and status of a completed test.
type Result struct {
	State            string // e.g., "finished", "errored"
	Errors           *[]IoSnykApiCommonError
	Warnings         *[]IoSnykApiCommonError
	TestID           *uuid.UUID         // The final Test ID (different from Job ID)
	Outcome          *PassFail          // Pass or Fail
	OutcomeReason    *TestOutcomeReason // Reason for the outcome (e.g., policy_breach)
	EffectiveSummary *FindingSummary    // Summary excluding suppressed findings
	RawSummary       *FindingSummary    // Summary including suppressed findings

	findings         []FindingData // Stores the actual findings
	findingsComplete bool          // True if all findings pages were fetched
	findingsError    error         // Error encountered during findings fetch, if any
	findingsOnce     sync.Once     // Ensures findings are fetched only once

	// Unexported reference to the parent handle to access client and orgID for fetching
	handle *testHandle // Populated when Result is created
}

// Return a new instance of the test client.
func NewTestClient(serverBaseUrl string, cfg Config, opts ...ClientOption) (TestClient, error) {
	llClient, err := NewClientWithResponses(serverBaseUrl, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	} else if cfg.PollInterval < MinPollInterval {
		cfg.PollInterval = MinPollInterval
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
			Type:       Tests,
		},
	}

	// Call the low-level client
	createTestParams := &CreateTestParams{Version: c.config.APIVersion}
	resp, err := c.lowLevelClient.CreateTestWithApplicationVndAPIPlusJSONBodyWithResponse(
		ctx,
		orgUUID,
		createTestParams,
		requestBody,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send create test request: %w", err)
	}

	// Extract and return the Job ID from the 202 Accepted response
	if resp.ApplicationvndApiJSON202 == nil {
		return nil, handleUnexpectedResponse(resp.StatusCode(), resp.Body, "creating test", orgUUID.String())
	}

	jobID := resp.ApplicationvndApiJSON202.Data.Id
	if jobID == uuid.Nil {
		return nil, fmt.Errorf("create test: job ID in response is nil (status %d)", resp.StatusCode())
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
// Returns nil on subsequent calls.
func (h *testHandle) Wait(ctx context.Context) error {
	errChan := make(chan error, 1) // hold a single error from the wait worker
	var firstRun bool

	h.runOnce.Do(func() {
		defer close(h.doneChan)
		var localErr error
		firstRun = true

		finalTestID, err := h.pollJobToCompletion(ctx)
		h.finalTestID = finalTestID
		// Store the error from polling, but continue if got a test ID anyway
		if err != nil {
			localErr = fmt.Errorf("polling job failed: %w", err)
			errChan <- localErr
			return
		}

		result, err := h.fetchResultStatus(ctx, *finalTestID)
		if err != nil {
			localErr = fmt.Errorf("failed to fetch final test status: %w", err)
			errChan <- localErr
			return
		}

		h.setResult(result)
		errChan <- nil
	})

	if !firstRun {
		return fmt.Errorf("wait operation was already initiated; result was/will be returned by the first call")
	}

	// Wait until the polling goroutine (started by runOnce.Do) finishes.
	<-h.doneChan
	return <-errChan
}

// Check status of a 200 OK response from GetJob.
// Returns true if polling should stop due to the job itself erroring,
// and an error if the job has errored. Otherwise, it returns false, nil.
func handleJobInProgress(resp *GetJobResponse, jobID uuid.UUID) (stopPolling bool, err error) {
	if resp.ApplicationvndApiJSON200 != nil {
		status := resp.ApplicationvndApiJSON200.Data.Attributes.Status
		if status == Errored {
			return true, fmt.Errorf("job reported status 'errored' (jobID: %s)", jobID)
		}
	}
	return false, nil
}

// Process a 303 See Other response from GetJob, extracting final Test ID from the Relationships.Test field.
// Returns testID on success, or an error if testID is not found. (jobID: %s for context)
func handleJobRedirect(resp *GetJobResponse, jobID uuid.UUID) (*uuid.UUID, error) {
	if resp.ApplicationvndApiJSON303 != nil && resp.ApplicationvndApiJSON303.Data.Relationships != nil {
		testID := resp.ApplicationvndApiJSON303.Data.Relationships.Test.Data.Id
		if testID == uuid.Nil {
			return nil, fmt.Errorf("job completed (303) but the final Test ID was missing in the response (jobID: %s)", jobID)
		}
		return &testID, nil
	} else {
		return nil, fmt.Errorf("job completed (303) but the final Test ID path was incomplete in the response (jobID: %s)", jobID)
	}
}

func withUnexpected() snyk_errors.Option {
	return func(e *snyk_errors.Error) {
		e.Classification = "UNEXPECTED"
	}
}

// handleUnexpectedResponse creates a detailed error from an HTTP response,
// attempting to parse Snyk-specific errors from the body.
// operationContext describes the action being performed (e.g., "creating test").
// identifier (optional) provides a specific ID (e.g., OrgID, JobID, TestID).
func handleUnexpectedResponse(statusCode int, body []byte, operationContext string, identifier string) error {
	detailMsg := fmt.Sprintf("unexpected response %s (status: %d)", operationContext, statusCode)
	if identifier != "" {
		detailMsg = fmt.Sprintf("unexpected response %s for ID %s (status: %d)", operationContext, identifier, statusCode)
	}
	baseErr := snyk.NewBadRequestError(detailMsg, withUnexpected())

	if len(body) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(body)
		if parseErr == nil && len(snykErrorList) > 0 {
			errsToJoin := []error{baseErr}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return errors.Join(errsToJoin...)
		}
	}
	return baseErr
}

// Query the job endpoint until we're redirected to its 'related' link containing results
func (h *testHandle) pollJobToCompletion(ctx context.Context) (*uuid.UUID, error) {
	ticker := time.NewTicker(h.client.config.PollInterval)
	defer ticker.Stop()

	getJobParams := &GetJobParams{Version: h.client.config.APIVersion}

	for {
		select {
		case <-ctx.Done():
			//TODO Operation Canceled - new error catalog error
			return nil, fmt.Errorf("context canceled while polling job: %w", ctx.Err())
		case <-ticker.C:
			resp, err := h.client.lowLevelClient.GetJobWithResponse(ctx, h.orgID, h.jobID, getJobParams)
			if err != nil {
				// Consider whether network errors should be retried
				return nil, fmt.Errorf("polling job request failed: %w", err)
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
				// TODO log to injected logger
				continue

			default:
				return nil, handleUnexpectedResponse(resp.StatusCode(), resp.Body, "polling job", h.jobID.String())
			}
		}
	}
}

// Get the test result outcome from polling and populate Result.
// Errors returned here are for the API interaction (e.g., bad response), not the test itself.
// Test state is captured in Result's State, Errors, and Warnings.
func (h *testHandle) fetchResultStatus(ctx context.Context, testID uuid.UUID) (*Result, error) {
	getTestParams := &GetTestParams{Version: h.client.config.APIVersion}
	resp, err := h.client.lowLevelClient.GetTestWithResponse(ctx, h.orgID, testID, getTestParams)
	if err != nil {
		return nil, fmt.Errorf("get test request failed (testID: %s): %w", testID, err)
	}

	if resp.ApplicationvndApiJSON200 == nil {
		return nil, handleUnexpectedResponse(resp.StatusCode(), resp.Body, "fetching test result", testID.String())
	}

	testData := resp.ApplicationvndApiJSON200.Data
	attrs := testData.Attributes
	status := &Result{
		TestID:           testData.Id,
		EffectiveSummary: attrs.EffectiveSummary,
		RawSummary:       attrs.RawSummary,
		handle:           h,
	}

	if attrs.State != nil {
		status.State = string(attrs.State.Execution)
		if attrs.State.Errors != nil && len(*attrs.State.Errors) > 0 {
			status.Errors = attrs.State.Errors
		}
		if attrs.State.Warnings != nil && len(*attrs.State.Warnings) > 0 {
			status.Warnings = attrs.State.Warnings
		}
	} else {
		status.State = "unknown" // API spec defines this as always set
	}

	if attrs.Outcome != nil {
		status.Outcome = &attrs.Outcome.Result
		status.OutcomeReason = attrs.Outcome.Reason
	}

	return status, nil
}

// Returns a channel signaling completion of Wait()
func (h *testHandle) Done() <-chan struct{} { return h.doneChan }

func (h *testHandle) Result() *Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.result
}

func (h *testHandle) setResult(status *Result) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.result = status
}

// Findings fetches and returns the findings associated with this test result.
// It fetches findings lazily on the first call. Subsequent calls return cached data.
//   - resultFindings: The list of findings.
//   - complete: True if all pages of findings were successfully fetched. False if an error
//     occurred during pagination or if the context was canceled, in which case
//     'resultFindings' may be partial.
//   - err: Any error encountered during the fetching process.
func (r *Result) Findings(ctx context.Context) (resultFindings []FindingData, complete bool, err error) {
	if r.TestID == nil || r.handle == nil {
		return nil, false, ErrInvalidStateForFindings
	}

	r.findingsOnce.Do(func() {
		fetchedData, isComplete, fetchErr := r.fetchFindingsInternal(ctx)
		r.findings = fetchedData
		r.findingsComplete = isComplete
		r.findingsError = fetchErr
	})
	return r.findings, r.findingsComplete, r.findingsError
}

// Logic to fetch Findings with pagination.
// Returns full or partial findings, true if all pages of findings were successfully fetched,
// and an error if one occurred.
func (r *Result) fetchFindingsInternal(ctx context.Context) ([]FindingData, bool, error) {
	if r.TestID == nil {
		return nil, false, fmt.Errorf("cannot fetch findings, TestID is nil in internal method")
	}
	testID := *r.TestID
	allFindings := []FindingData{}
	var startingAfter *string

	listParams := &ListFindingsParams{
		Version: r.handle.client.config.APIVersion,
		Limit:   ptr(int8(MaxFindingsPerPage)),
	}

	for {
		select {
		case <-ctx.Done():
			//TODO Operation Canceled - new error catalog error
			return r.handleFindingsError(ErrFindingsFetchCanceled, allFindings)
		default:
			// Continue fetching
		}

		listParams.StartingAfter = startingAfter
		resp, err := r.handle.client.lowLevelClient.ListFindingsWithResponse(ctx, r.handle.orgID, testID, listParams)
		if err != nil {
			return r.handleFindingsError(fmt.Errorf("%w: %w", ErrFindingsPageRequest, err), allFindings)
		}

		pageData, nextCursor, err := r.processFindingsPage(resp)
		if err != nil {
			return r.handleFindingsError(err, allFindings)
		}

		if pageData != nil {
			allFindings = append(allFindings, pageData...)
		}

		if nextCursor == nil {
			return allFindings, true, nil // Successfully fetched all
		}
		startingAfter = nextCursor
	}
}

// processFindingsPage processes a single page of findings response.
// It returns the data from the page, the next cursor, or an error.
func (r *Result) processFindingsPage(resp *ListFindingsResponse) ([]FindingData, *string, error) {
	if resp.ApplicationvndApiJSON200 == nil {
		return nil, nil, ErrFindingsPageResponse
	}

	responseData := resp.ApplicationvndApiJSON200
	if responseData.Data == nil && responseData.Links.Next != nil {
		// This indicates an inconsistent API response (e.g., claims there's a next page but provides no data for current)
		return nil, nil, ErrFindingsPageData
	}

	if responseData.Links.Next == nil {
		return responseData.Data, nil, nil // No more pages
	}

	nextCursor, err := r.extractNextCursor(responseData.Links.Next)
	if err != nil {
		return responseData.Data, nil, err // fetch error but potentially with Findings
	}

	return responseData.Data, nextCursor, nil
}

// extractNextCursor parses the 'next' link and returns the 'starting_after' cursor.
// Any failure in this function will return ErrFindingsNextPageCursor.
func (r *Result) extractNextCursor(nextLink *IoSnykApiCommonLinkProperty) (*string, error) {
	if nextLink == nil {
		return nil, ErrFindingsNextPageCursor
	}

	var nextLinkStr string
	linkStr, errLinkStr := nextLink.AsIoSnykApiCommonLinkString()
	if errLinkStr == nil {
		nextLinkStr = linkStr
	} else {
		linkObj, errObj := nextLink.AsIoSnykApiCommonLinkObject()
		if errObj != nil {
			// Failed to parse as string or object
			return nil, ErrFindingsNextPageCursor
		}
		nextLinkStr = linkObj.Href
	}

	if nextLinkStr == "" { // Ensure Href was not empty if it was an object
		return nil, ErrFindingsNextPageCursor
	}

	parsedNext, errParse := url.Parse(nextLinkStr)
	if errParse != nil {
		return nil, ErrFindingsNextPageCursor
	}

	cursor := parsedNext.Query().Get("starting_after")
	if cursor == "" {
		return nil, ErrFindingsNextPageCursor
	}
	return &cursor, nil
}

// Helper to consistently format errors and decide whether to return partial results.
func (r *Result) handleFindingsError(err error, partialFindings []FindingData) ([]FindingData, bool, error) {
	if len(partialFindings) > 0 {
		return partialFindings, false, fmt.Errorf("%w, returning partial results", err)
	}
	return nil, false, err
}

// ptr returns a pointer to the given value. Useful for optional fields.
func ptr[T any](v T) *T {
	return &v
}
