package testapi_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// Configures the newTestAPIMockHandler.
type TestAPIHandlerConfig struct {
	OrgID                  uuid.UUID
	JobID                  uuid.UUID
	TestID                 uuid.UUID
	APIVersion             string                       // Used for assertions and in mock responses
	ExpectedCreateTestBody *testapi.TestRequestBody     // Optional: if provided, POST /tests body is asserted
	PollCounter            *atomic.Int32                // Optional: counter for GET /test_jobs calls, incremented by the handler
	JobPollResponses       []JobPollResponseConfig      // Defines behavior for each GET /test_jobs poll attempt
	FinalTestResult        FinalTestResultConfig        // Defines behavior for GET /tests/{testID}
	FindingsConfig         *FindingsHandlerConfig       // Optional: if provided, enables GET /tests/{testID}/findings mocking
	ServerURLProvider      func(r *http.Request) string // Function to get the server base URL
}

// Defines the response for a single GET /test_jobs poll.
type JobPollResponseConfig struct {
	Status         testapi.TestExecutionStates // If set, returns standard status response (e.g., Pending, Errored)
	ShouldRedirect bool                        // If true, returns a 303 redirect to the final test result
	CustomHandler  http.HandlerFunc            // If set, this custom handler is used for this poll stage
}

// Defines the response for GET /tests/{testID}.
type FinalTestResultConfig struct {
	Outcome       testapi.PassFail
	OutcomeReason *testapi.TestOutcomeReason
	ApiErrors     *[]testapi.IoSnykApiCommonError
	ApiWarnings   *[]testapi.IoSnykApiCommonError
	CustomHandler http.HandlerFunc // If set, this custom handler is used instead of standard result mock
}

// Configures mocking for GET /tests/{testID}/findings.
type FindingsHandlerConfig struct {
	APIVersion         string        // API version to expect in query params
	PageCounter        *atomic.Int32 // Counter for pagination calls
	EndpointCalled     *atomic.Bool  // Flag to indicate if the endpoint was called
	TotalFindingsPages int           // How many pages of findings to simulate before returning empty
}

// Creates a mock HTTP server for the full Test API workflow:
// 1. POST /tests
// 2. GET /test_jobs/<job_id>
// 3. GET /tests/<test_id>
// 4. GET /tests/<test_id>/findings
func newTestAPIMockHandler(t *testing.T, config TestAPIHandlerConfig) http.HandlerFunc {
	t.Helper()
	pollAttemptCounter := new(atomic.Int32)

	if config.ServerURLProvider == nil {
		config.ServerURLProvider = serverURLFromRequest
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		expectedTestPath := fmt.Sprintf("/orgs/%s/tests", config.OrgID)
		expectedJobPath := fmt.Sprintf("/orgs/%s/test_jobs/%s", config.OrgID, config.JobID)
		expectedResultPath := fmt.Sprintf("/orgs/%s/tests/%s", config.OrgID, config.TestID)
		expectedFindingsPath := fmt.Sprintf("/orgs/%s/tests/%s/findings", config.OrgID, config.TestID)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == expectedTestPath:
			handleCreateTestRequest(t, w, r, config)
		case r.Method == http.MethodGet && r.URL.Path == expectedJobPath:
			handlePollJobRequest(t, w, r, config, pollAttemptCounter, expectedResultPath)
		case r.Method == http.MethodGet && r.URL.Path == expectedResultPath:
			handleTestResultRequest(t, w, r, config)
		case config.FindingsConfig != nil && r.Method == http.MethodGet && r.URL.Path == expectedFindingsPath:
			handleTestFindingsRequest(t, w, r, config)
		default:
			errMsg := fmt.Sprintf("Mock server: Unexpected request: %s %s", r.Method, r.URL.Path)
			t.Log(errMsg)
			http.Error(w, errMsg, http.StatusNotFound)
		}
	}
}

// handle POST /tests -- creates a test
func handleCreateTestRequest(t *testing.T, w http.ResponseWriter, r *http.Request, config TestAPIHandlerConfig) {
	t.Helper()
	assert.Equal(t, config.APIVersion, r.URL.Query().Get("version"))
	assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

	if config.ExpectedCreateTestBody != nil {
		bodyBytes, bodyErr := io.ReadAll(r.Body)
		require.NoError(t, bodyErr)
		defer r.Body.Close()
		expectedBodyBytes, err := json.Marshal(config.ExpectedCreateTestBody)
		require.NoError(t, err)
		assert.JSONEq(t, string(expectedBodyBytes), string(bodyBytes))
	}

	startResp := mockStartTestResponse(t, config.JobID)
	w.WriteHeader(http.StatusAccepted)
	_, err := w.Write(startResp)
	assert.NoError(t, err)
}

// handle GET /test_jobs/<job_id> -- poll for job to finish: repeats 200 until 303 redirect to results
func handlePollJobRequest(t *testing.T, w http.ResponseWriter, r *http.Request, config TestAPIHandlerConfig, pollAttemptCounter *atomic.Int32, expectedResultPath string) {
	t.Helper()
	currentPoll := pollAttemptCounter.Load()
	pollAttemptCounter.Add(1)
	if config.PollCounter != nil {
		config.PollCounter.Add(1)
	}

	require.Less(t, int(currentPoll), len(config.JobPollResponses), "More poll attempts than configured responses for GET /test_jobs")
	pollRespCfg := config.JobPollResponses[currentPoll]

	if pollRespCfg.CustomHandler != nil {
		pollRespCfg.CustomHandler(w, r)
		return
	}

	if pollRespCfg.ShouldRedirect {
		relatedLink := fmt.Sprintf("%s%s", config.ServerURLProvider(r), expectedResultPath)
		jobResp := mockJobRedirectResponse(t, config.JobID, relatedLink, config.TestID)
		w.Header().Set("Location", relatedLink)
		w.WriteHeader(http.StatusSeeOther)
		_, err := w.Write(jobResp)
		assert.NoError(t, err)
	} else {
		jobResp := mockJobStatusResponse(t, config.JobID, pollRespCfg.Status)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(jobResp)
		assert.NoError(t, err)
	}
}

// handle GET /tests/<test_id> -- test results, target of polling's 303 redirect
func handleTestResultRequest(t *testing.T, w http.ResponseWriter, r *http.Request, config TestAPIHandlerConfig) {
	t.Helper()
	if config.FinalTestResult.CustomHandler != nil {
		config.FinalTestResult.CustomHandler(w, r)
		return
	}
	resultResp := mockTestResultResponse(t, config.TestID,
		config.FinalTestResult.Outcome,
		config.FinalTestResult.OutcomeReason,
		config.FinalTestResult.ApiErrors,
		config.FinalTestResult.ApiWarnings,
	)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(resultResp)
	assert.NoError(t, err)
}

// handle GET /tests/<test_id>/findings -- paginated test findings
func handleTestFindingsRequest(t *testing.T, w http.ResponseWriter, r *http.Request, config TestAPIHandlerConfig) {
	t.Helper()
	cfg := config.FindingsConfig
	if cfg.EndpointCalled != nil {
		cfg.EndpointCalled.Store(true)
	}
	currentPage := int32(1)
	if cfg.PageCounter != nil {
		currentPage = cfg.PageCounter.Add(1)
	}

	assert.Equal(t, cfg.APIVersion, r.URL.Query().Get("version"))
	assert.Equal(t, "100", r.URL.Query().Get("limit"))

	if currentPage == 1 {
		assert.Empty(t, r.URL.Query().Get("starting_after"), "GET /findings starting_after should be empty on first page")
	} else {
		assert.NotEmpty(t, r.URL.Query().Get("starting_after"), "GET /findings starting_after should be present on subsequent pages")
	}

	var nextLink *string
	var shouldHaveDataThisPage bool

	if currentPage <= int32(cfg.TotalFindingsPages) {
		shouldHaveDataThisPage = true
		nextCursor := fmt.Sprintf("page%dcursor", currentPage+1)
		linkURL := fmt.Sprintf("%s%s?version=%s&limit=100&starting_after=%s", config.ServerURLProvider(r), r.URL.Path, cfg.APIVersion, nextCursor)
		nextLink = &linkURL
	} else {
		shouldHaveDataThisPage = false
		nextLink = nil
	}

	findingsResp := mockListFindingsResponse(t, nextLink, shouldHaveDataThisPage)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(findingsResp)
	assert.NoError(t, err)
}

// newApiErrorResponder creates a handler that returns a specific API error for POST /tests.
func newApiErrorResponder(t *testing.T, orgID uuid.UUID, statusCode int, errorResponse testapi.IoSnykApiCommonErrorDocument) http.HandlerFunc {
	t.Helper()
	errorBodyBytes, err := json.Marshal(errorResponse)
	require.NoError(t, err)

	return func(w http.ResponseWriter, r *http.Request) {
		expectedPath := fmt.Sprintf("/orgs/%s/tests", orgID)
		if r.URL.Path != expectedPath || r.Method != http.MethodPost {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(statusCode)
		_, writeErr := w.Write(errorBodyBytes)
		assert.NoError(t, writeErr)
	}
}

// --- support functions ---

// Parses a sample JSON string and returns the depGraph part.
// Fails the test immediately if unmarshalling fails.
func depGraphFromJSON(t *testing.T) testapi.IoSnykApiV1testdepgraphRequestDepGraph {
	t.Helper()

	jsonImport := `{
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
		}`

	var topLevelStruct struct {
		DepGraph testapi.IoSnykApiV1testdepgraphRequestDepGraph `json:"depGraph"`
	}
	err := json.Unmarshal([]byte(jsonImport), &topLevelStruct)
	require.NoError(t, err)

	return topLevelStruct.DepGraph
}

// Return a depGraph to run a test on
func newDepGraphTestSubject(t *testing.T) testapi.TestSubjectCreate {
	t.Helper()
	testSubject := testapi.TestSubjectCreate{}
	err := testSubject.FromDepGraphSubjectCreate(testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
		DepGraph: depGraphFromJSON(t),
		Locator: testapi.LocalPathLocator{
			Paths: []string{"package.json"},
			Type:  testapi.LocalPath,
		},
	})
	require.NoError(t, err)
	return testSubject
}

// Sets up an httptest server. Returns the server and a cleanup function.
func startMockServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	cleanup := func() { server.Close() }
	return server, cleanup
}

// Creates a new test http.Client, using transport and timeout from the provided server's client.
func newTestHTTPClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	baseClient := server.Client()
	return &http.Client{
		Transport: baseClient.Transport,
		Timeout:   baseClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Override test client's autofollow of redirects so that TestAPI gets them.
			return http.ErrUseLastResponse
		},
	}
}

// Extracts the base URL (scheme + host) from an incoming request.
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
	require.NoError(t, err)
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
	require.NoError(t, err)
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /test_jobs/{job_id} redirect call (303 See Other).
func mockJobRedirectResponse(t *testing.T, jobID openapi_types.UUID, relatedLink string, testID openapi_types.UUID) []byte {
	t.Helper()
	attributes := testapi.JobAttributes{
		Status:    testapi.Finished,
		CreatedAt: time.Now().Add(-1 * time.Minute),
	}

	links := testapi.GetJob_303_Links{}
	var linkProp testapi.IoSnykApiCommonLinkProperty
	err := linkProp.FromIoSnykApiCommonLinkString(relatedLink)
	require.NoError(t, err)
	links.Related = &linkProp

	responseData := testapi.JobData{
		Attributes: attributes,
		Id:         jobID,
		Type:       testapi.TestJobs,
		Relationships: &testapi.JobRelationships{
			Test: testapi.JobRelationshipField{
				Data: struct {
					Id   openapi_types.UUID                   `json:"id"`
					Type testapi.JobRelationshipFieldDataType `json:"type"`
				}{
					Id:   testID,
					Type: testapi.JobRelationshipFieldDataTypeTests,
				},
			},
		},
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
	require.NoError(t, err)
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /tests/{test_id} call (200 OK).
func mockTestResultResponse(
	t *testing.T,
	testID openapi_types.UUID,
	outcomeResult testapi.PassFail,
	outcomeReason *testapi.TestOutcomeReason,
	apiErrors *[]testapi.IoSnykApiCommonError,
	apiWarnings *[]testapi.IoSnykApiCommonError,
) []byte {
	t.Helper()
	attributes := testapi.TestAttributes{
		Outcome: &testapi.TestOutcome{
			Result: outcomeResult,
			Reason: outcomeReason,
		},
		State: &testapi.TestState{
			Execution: testapi.Finished,
			Errors:    apiErrors,
			Warnings:  apiWarnings,
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
	require.NoError(t, err)
	return responseBodyBytes
}

// Creates a marshaled JSON response for the GET /tests/{test_id}/findings call (200 OK).
// Uses the anonymous struct within ListFindingsResponse for the 200 response.
// nextLink: an optional link to include for pagination.
// hasData: a boolean indicating if this response page should contain actual finding data.
func mockListFindingsResponse(t *testing.T, nextLink *string, hasData bool) []byte {
	t.Helper()

	// Use a fixed UUID for deterministic testing if needed, or generate new ones
	// findingID := uuid.MustParse("...")

	findingID := uuid.New()
	findingTypeConst := testapi.FindingTypeSca
	findingKey := "ABCD-FINDING-PROBLEM-HIGH"
	findingTitle := "XYZ High Sev"
	findingDesc := "Finding example high sev"
	cveID := "CVE-2024-12345"
	filePath := "package-lock.json"
	lineNum := int(42)

	// Create a mock Problem (CVE)
	var problem testapi.Problem
	err := problem.FromCveProblem(testapi.CveProblem{
		Id:     cveID,
		Source: testapi.Cve,
	})
	require.NoError(t, err)

	// Create a mock Location (SourceFile)
	var location testapi.FindingLocation
	err = location.FromSourceLocation(testapi.SourceLocation{
		FilePath: filePath,
		FromLine: lineNum,
		Type:     testapi.Source,
	})
	require.NoError(t, err)

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

	// Conditionally create findings data based on whether a next link is provided
	// (to simulate pagination end)
	var responseData []testapi.FindingData
	if hasData {
		responseData = []testapi.FindingData{findingData}
	} else {
		responseData = []testapi.FindingData{}
	}

	// Create links, including 'next' if provided (passed in by the caller)
	links := testapi.IoSnykApiCommonPaginatedLinks{}
	if nextLink != nil {
		var nextLinkProp testapi.IoSnykApiCommonLinkProperty
		err = nextLinkProp.FromIoSnykApiCommonLinkString(*nextLink)
		require.NoError(t, err)
		links.Next = &nextLinkProp
	}

	// Instantiate the anonymous struct defined within ListFindingsResponse.ApplicationvndApiJSON200
	mockResponseBody := struct {
		Data    []testapi.FindingData                 `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi        `json:"jsonapi"`
		Links   testapi.IoSnykApiCommonPaginatedLinks `json:"links"`
		Meta    *testapi.IoSnykApiCommonMeta          `json:"meta,omitempty"`
	}{
		Data: responseData,
		Jsonapi: testapi.IoSnykApiCommonJsonApi{
			Version: testapi.N10, // Standard JSON API version
		},
		Links: links, // Use the prepared links (with optional 'next')
	}

	responseBodyBytes, err := json.Marshal(mockResponseBody)
	require.NoError(t, err)
	return responseBodyBytes
}

// ptr returns a pointer to the given value. Useful for optional fields.
func ptr[T any](v T) *T {
	return &v
}
