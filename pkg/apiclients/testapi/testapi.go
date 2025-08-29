package testapi

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

//go:generate go tool github.com/golang/mock/mockgen -source=testapi.go -destination ../mocks/testapi.go -package mocks -imports testapi=github.com/snyk/go-application-framework/pkg/apiclients/testapi

// config holds configuration for the test API client, set using ConfigOption functions.
type config struct {
	PollInterval          time.Duration // Default: 2000ms, Min: 1000ms
	PollTimeout           time.Duration // Max total time for polling. Default: 30 min.
	APIVersion            string
	Logger                *zerolog.Logger
	lowLevelClientOptions []ClientOption // Options for the oapi-codegen client
	jitterFunc            func(time.Duration) time.Duration
}

// ConfigOption allows setting custom parameters during construction
type ConfigOption func(c *config)

// WithPollInterval sets the poll interval for the test client.
// Defaults to 2 seconds if unset or <= 0.
// Minimum interval is 1 second.
func WithPollInterval(d time.Duration) ConfigOption {
	return func(c *config) {
		if d <= 0 {
			c.PollInterval = DefaultPollInterval
		} else {
			c.PollInterval = max(d, MinPollInterval)
		}
	}
}

// WithPollTimeout sets the maximum total time for polling.
func WithPollTimeout(d time.Duration) ConfigOption {
	return func(c *config) {
		c.PollTimeout = d
	}
}

// WithAPIVersion sets the API version for the test client.
func WithAPIVersion(v string) ConfigOption {
	return func(c *config) {
		if v == "" {
			c.APIVersion = DefaultAPIVersion
		} else {
			c.APIVersion = v
		}
	}
}

// WithLogger sets the logger for the test client.
func WithLogger(l *zerolog.Logger) ConfigOption {
	return func(c *config) {
		c.Logger = l
	}
}

// WithCustomHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithCustomHTTPClient(doer HttpRequestDoer) ConfigOption {
	return func(c *config) {
		opt := WithHTTPClient(doer)
		c.lowLevelClientOptions = append(c.lowLevelClientOptions, opt)
	}
}

// WithCustomRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithCustomRequestEditorFn(fn RequestEditorFn) ConfigOption {
	return func(c *config) {
		opt := WithRequestEditorFn(fn)
		c.lowLevelClientOptions = append(c.lowLevelClientOptions, opt)
	}
}

// WithJitterFunc allows setting a custom jitter function for polling.
func WithJitterFunc(fn func(time.Duration) time.Duration) ConfigOption {
	return func(c *config) {
		c.jitterFunc = fn
	}
}

type client struct {
	lowLevelClient ClientWithResponsesInterface
	config         config
	logger         *zerolog.Logger
}

// TestResult defines the contract for accessing test result information.
type TestResult interface {
	GetTestID() *uuid.UUID
	GetTestConfiguration() *TestConfiguration
	GetCreatedAt() *time.Time
	GetTestSubject() TestSubject
	GetSubjectLocators() *[]TestSubjectLocator

	GetExecutionState() TestExecutionStates
	GetErrors() *[]IoSnykApiCommonError
	GetWarnings() *[]IoSnykApiCommonError

	GetPassFail() *PassFail
	GetOutcomeReason() *TestOutcomeReason
	GetBreachedPolicies() *PolicyRefSet

	GetEffectiveSummary() *FindingSummary
	GetRawSummary() *FindingSummary

	Findings(ctx context.Context) (resultFindings []FindingData, complete bool, err error)
}

// TestHandle allows for starting a test and waiting on its response
type TestHandle interface {
	Wait(ctx context.Context) error
	Done() <-chan struct{}
	Result() TestResult
}

type testHandle struct {
	client *client
	orgID  uuid.UUID
	jobID  uuid.UUID

	runOnce  sync.Once
	doneChan chan struct{}
	mu       sync.Mutex // protects result
	result   TestResult

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
	DefaultAPIVersion   = "2024-10-15"
)

// Predefined errors for findings operations
var (
	ErrInvalidStateForFindings = errors.New("cannot fetch findings: test ID or internal handle is missing")
	ErrFindingsFetchCanceled   = errors.New("findings fetch operation was canceled")
	ErrFindingsPageRequest     = errors.New("failed to request a page of findings")
	ErrFindingsPageResponse    = errors.New("unexpected API response when fetching findings page")
	ErrFindingsPageData        = errors.New("invalid data in findings page API response")
	ErrFindingsNextPageCursor  = errors.New("failed to determine next findings page cursor from API response")
)

// StartTestParams defines parameters for the high-level StartTest function.
type StartTestParams struct {
	OrgID       string
	Subject     TestSubjectCreate
	LocalPolicy *LocalPolicy
}

// testResult is the concrete implementation of the TestResult interface for
// accessing summary and findings data of a completed test.
type testResult struct {
	TestID            *uuid.UUID // The final Test ID (different from Job ID)
	TestConfiguration *TestConfiguration
	CreatedAt         *time.Time
	TestSubject       TestSubject
	SubjectLocators   *[]TestSubjectLocator

	ExecutionState TestExecutionStates // e.g., "finished", "errored"
	Errors         *[]IoSnykApiCommonError
	Warnings       *[]IoSnykApiCommonError

	PassFail         *PassFail          // Pass or Fail
	OutcomeReason    *TestOutcomeReason // Reason for the outcome (e.g., policy_breach)
	BreachedPolicies *PolicyRefSet      // A set of local or managed policies

	EffectiveSummary *FindingSummary // Summary excluding suppressed findings
	RawSummary       *FindingSummary // Summary including suppressed findings

	findings         []FindingData // Stores the actual findings
	findingsComplete bool          // True if all findings pages were fetched
	findingsError    error         // Error encountered during findings fetch, if any
	findingsOnce     sync.Once     // Ensures findings are fetched only once

	// Unexported reference to the parent handle to access client and orgID for fetching
	handle *testHandle // Populated when testResult is created
}

// GetExecutionState returns the execution state of the test.
func (r *testResult) GetExecutionState() TestExecutionStates { return r.ExecutionState }

// GetErrors returns any API errors encountered during the test execution.
func (r *testResult) GetErrors() *[]IoSnykApiCommonError { return r.Errors }

// GetWarnings returns any API warnings encountered during the test execution.
func (r *testResult) GetWarnings() *[]IoSnykApiCommonError { return r.Warnings }

// GetTestID returns the final Test ID.
func (r *testResult) GetTestID() *uuid.UUID { return r.TestID }

// GetPassFail returns the pass/fail outcome of the test.
func (r *testResult) GetPassFail() *PassFail { return r.PassFail }

// GetOutcomeReason returns the reason for the test outcome.
func (r *testResult) GetOutcomeReason() *TestOutcomeReason { return r.OutcomeReason }

// GetBreachedPolicies returns the policies that were breached.
func (r *testResult) GetBreachedPolicies() *PolicyRefSet { return r.BreachedPolicies }

// GetTestConfiguration returns the test configuration.
func (r *testResult) GetTestConfiguration() *TestConfiguration { return r.TestConfiguration }

// GetCreatedAt returns the creation timestamp of the test.
func (r *testResult) GetCreatedAt() *time.Time { return r.CreatedAt }

// GetTestSubject returns the test subject.
func (r *testResult) GetTestSubject() TestSubject { return r.TestSubject }

// GetSubjectLocators returns the subject locators.
func (r *testResult) GetSubjectLocators() *[]TestSubjectLocator { return r.SubjectLocators }

// GetEffectiveSummary returns the summary excluding suppressed findings.
func (r *testResult) GetEffectiveSummary() *FindingSummary { return r.EffectiveSummary }

// GetRawSummary returns the summary including suppressed findings.
func (r *testResult) GetRawSummary() *FindingSummary { return r.RawSummary }

// NewTestClient returns a new instance of the test client, configured with the provided options.
func NewTestClient(serverBaseUrl string, options ...ConfigOption) (TestClient, error) {
	cfg := config{
		PollInterval: DefaultPollInterval,
		APIVersion:   DefaultAPIVersion,
		jitterFunc:   Jitter,
	}

	for _, opt := range options {
		opt(&cfg)
	}

	llClient, err := NewClientWithResponses(serverBaseUrl, cfg.lowLevelClientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create low-level test client: %w", err)
	}

	var clLogger *zerolog.Logger
	if cfg.Logger != nil {
		clLogger = cfg.Logger
	} else {
		nopLogger := zerolog.Nop()
		clLogger = &nopLogger
	}

	return &client{
		lowLevelClient: llClient,
		config:         cfg,
		logger:         clLogger,
	}, nil
}

// Create the initial test and return a handle to poll it
func (c *client) StartTest(ctx context.Context, params StartTestParams) (TestHandle, error) {
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
	if params.LocalPolicy != nil {
		testAttributes.Config = &TestConfiguration{
			LocalPolicy: params.LocalPolicy,
		}
	}
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

		// Check if finalTestID is nil before dereferencing
		if finalTestID == nil {
			localErr = fmt.Errorf("polling job completed without a final test ID")
			errChan <- localErr
			return
		}

		resultData, err := h.fetchResultStatus(ctx, *finalTestID)
		if err != nil {
			localErr = fmt.Errorf("failed to fetch final test status: %w", err)
			errChan <- localErr
			return
		}

		h.setResult(resultData)
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

// Modify error catalog entry with an unexpected status code
func asUnexpected(statusCode int) snyk_errors.Option {
	return func(e *snyk_errors.Error) {
		e.Classification = "UNEXPECTED"
		e.StatusCode = statusCode
	}
}

// Modify error catalog entry to be a warning with no HTTP status (issued locally)
func asCanceled() snyk_errors.Option {
	return func(e *snyk_errors.Error) {
		e.StatusCode = 0
		e.Level = "warn"
	}
}

// Combine remote errors from the JSON body, if present. Otherwise return an unexpected error with the given status code.
func handleUnexpectedResponse(statusCode int, body []byte, operationContext string, identifier string) error {
	if len(body) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(body)
		if parseErr == nil && len(snykErrorList) > 0 {
			errsToJoin := []error{}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return errors.Join(errsToJoin...)
		}
	}

	detailMsg := fmt.Sprintf("unexpected response %s (status: %d)", operationContext, statusCode)
	if identifier != "" {
		detailMsg = fmt.Sprintf("unexpected response %s for ID %s (status: %d)", operationContext, identifier, statusCode)
	}
	return snyk.NewBadRequestError(detailMsg, asUnexpected(statusCode))
}

func contextCanceledError(operationDescription string, contextError error) error {
	detailMsg := operationDescription
	if contextError != nil {
		detailMsg = fmt.Sprintf("%s: %s", detailMsg, contextError.Error())
	}
	return snyk.NewBadRequestError(detailMsg, asCanceled())
}

// Query the job endpoint until we're redirected to its 'related' link containing results
func (h *testHandle) pollJobToCompletion(ctx context.Context) (*uuid.UUID, error) {
	cfg := h.client.config

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	getJobParams := &GetJobParams{Version: h.client.config.APIVersion}

	for {
		select {
		case <-ctx.Done():
			return nil, contextCanceledError("context canceled while polling job", ctx.Err())
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
				ticker.Reset(cfg.jitterFunc(cfg.PollInterval))
				continue

			case http.StatusSeeOther:
				// Job finished, redirecting to Test resource
				testID, redirectErr := handleJobRedirect(resp, h.jobID)
				if redirectErr != nil {
					return nil, redirectErr
				}
				return testID, nil

			case http.StatusNotFound:
				h.client.logger.Warn().
					Str("orgID", h.orgID.String()).
					Str("jobID", h.jobID.String()).
					Msg("Job polling returned 404 Not Found, continuing polling in case of delayed job creation")
				ticker.Reset(cfg.jitterFunc(cfg.PollInterval))
				continue

			default:
				return nil, handleUnexpectedResponse(resp.StatusCode(), resp.Body, "polling job", h.jobID.String())
			}
		}
	}
}

// Get the test result outcome from polling and populate testResult.
// Errors returned here are for the API interaction (e.g., bad response), not the test itself.
// Test state is captured in testResult's State, Errors, and Warnings.
func (h *testHandle) fetchResultStatus(ctx context.Context, testID uuid.UUID) (TestResult, error) {
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
	result := &testResult{
		TestID:            testData.Id,
		TestConfiguration: attrs.Config,
		CreatedAt:         attrs.CreatedAt,
		TestSubject:       attrs.Subject,
		SubjectLocators:   attrs.SubjectLocators,
		EffectiveSummary:  attrs.EffectiveSummary,
		RawSummary:        attrs.RawSummary,
		handle:            h,
	}

	if attrs.State != nil {
		result.ExecutionState = attrs.State.Execution
		if attrs.State.Errors != nil && len(*attrs.State.Errors) > 0 {
			result.Errors = attrs.State.Errors
		}
		if attrs.State.Warnings != nil && len(*attrs.State.Warnings) > 0 {
			result.Warnings = attrs.State.Warnings
		}
	} else {
		result.ExecutionState = TestExecutionStates("unknown") // API spec defines this as always set
	}

	if attrs.Outcome != nil {
		result.PassFail = &attrs.Outcome.Result
		result.OutcomeReason = attrs.Outcome.Reason
		result.BreachedPolicies = attrs.Outcome.BreachedPolicies
	}

	return result, nil
}

// Returns a channel signaling completion of Wait()
func (h *testHandle) Done() <-chan struct{} { return h.doneChan }

func (h *testHandle) Result() TestResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.result
}

func (h *testHandle) setResult(status TestResult) {
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
func (r *testResult) Findings(ctx context.Context) (resultFindings []FindingData, complete bool, err error) {
	if r.GetTestID() == nil || r.handle == nil {
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
func (r *testResult) fetchFindingsInternal(ctx context.Context) ([]FindingData, bool, error) {
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
			contextErr := contextCanceledError(ErrFindingsFetchCanceled.Error(), ctx.Err())
			return r.handleFindingsError(contextErr, allFindings)
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
func (r *testResult) processFindingsPage(resp *ListFindingsResponse) ([]FindingData, *string, error) {
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
func (r *testResult) extractNextCursor(nextLink *IoSnykApiCommonLinkProperty) (*string, error) {
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
func (r *testResult) handleFindingsError(err error, partialFindings []FindingData) ([]FindingData, bool, error) {
	if len(partialFindings) > 0 {
		return partialFindings, false, fmt.Errorf("%w, returning partial results", err)
	}
	return nil, false, err
}

// ptr returns a pointer to the given value. Useful for optional fields.
func ptr[T any](v T) *T {
	return &v
}

// Jitter returns a random duration between 0.5 and 1.5 of the given duration.
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	minDur := int64(float64(d) * 0.5)
	maxDur := int64(float64(d) * 1.5)
	return time.Duration(rand.Int63n(maxDur-minDur) + minDur)
}
