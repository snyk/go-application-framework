//nolint:goconst,gocritic // demo script
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"

	// Separate imports for now to distinguish ll and hl APIs. v20241015defs is the low level API.
	"github.com/snyk/go-application-framework/internal/api/testapi"
	v20241015defs "github.com/snyk/go-application-framework/internal/api/testapi"
)

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func orgUUID() (uuid.UUID, error) {
	orgID := os.Getenv("SNYK_CFG_ORG")
	if orgID == "" {
		return uuid.Nil, fmt.Errorf("SNYK_CFG_ORG must be set to a valid UUID")
	}
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("SNYK_CFG_ORG must be a valid UUID: %w", err)
	}
	return orgUUID, nil
}

func snykAPI() string {
	url := os.Getenv("SNYK_API")
	if url == "" {
		url = "http://localhost:8080"
	}
	return url + "/closed-beta/"
}

func httpclient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &retryRoundTripper{
			&authRoundTripper{http.DefaultTransport},
		},
	}
}

type retryRoundTripper struct{ http.RoundTripper }
type authRoundTripper struct{ http.RoundTripper }

func (rt *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var result http.Response
	err := backoff.Retry(func() error {
		resp, err := rt.RoundTripper.RoundTrip(req)
		// If we're retrying, close the response body so that we don't leak
		// memory from failed attempts.
		if err != nil {
			fmt.Println("HTTP error: ", resp, err)

			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			return backoff.Permanent(err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			if resp.Body != nil {
				resp.Body.Close()
			}
			return fmt.Errorf("too many requests")
		}

		result = *resp
		return nil
	}, backoff.NewExponentialBackOff())
	if err != nil {
		return nil, fmt.Errorf("retry failed: %w", err)
	}
	return &result, nil
}

func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token := os.Getenv("SNYK_TOKEN")
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	} else {
		log.Println("Warning: SNYK_TOKEN not set, making unauthenticated request.")
	}
	return rt.RoundTripper.RoundTrip(req)
}

func depGraphFromArgs() (testapi.IoSnykApiV1testdepgraphRequestDepGraph, error) {
	if len(os.Args) != 2 {
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{},
			fmt.Errorf("requires DepGraph filename as input")
	}

	var contents []byte
	var err error
	if strings.TrimSpace(os.Args[1]) != "-" {
		filepath := path.Clean(os.Args[1])
		fmt.Println("Loading DepGraph from file: ", filepath)
		contents, err = os.ReadFile(filepath)
		if err != nil {
			return testapi.IoSnykApiV1testdepgraphRequestDepGraph{},
				fmt.Errorf("reading test file '%s' failed: %w", filepath, err)
		}
	} else {
		fmt.Println("Loading DepGraph from stdin")
		contents, err = io.ReadAll(os.Stdin)
		if err != nil {
			return testapi.IoSnykApiV1testdepgraphRequestDepGraph{},
				fmt.Errorf("unable to load from stdin: %w", err)
		}
	}

	// use only the top-level "depGraph" field
	var depGraphStruct struct {
		DepGraph testapi.IoSnykApiV1testdepgraphRequestDepGraph `json:"depGraph"`
	}
	err = json.Unmarshal(contents, &depGraphStruct)
	if err != nil {
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{},
			fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
	}

	return depGraphStruct.DepGraph, nil
}

func run() error {
	ctx := context.Background()

	orgID, err := orgUUID()
	if err != nil {
		return fmt.Errorf("failed to get org ID: %w", err)
	}
	orgIDStr := orgID.String()

	assetID := uuid.New()

	// Load DepGraph file from command line
	var depGraph testapi.IoSnykApiV1testdepgraphRequestDepGraph
	depGraph, err = depGraphFromArgs()
	if err != nil {
		return err
	}

	// Prepare high-level StartTest parameters

	ts := testapi.TestSubjectCreate{}
	err = ts.FromDepGraphSubjectCreate(testapi.DepGraphSubjectCreate{
		AssetId:     assetID,
		DepGraph:    depGraph,
		SourceFiles: []string{"package.json"},
	})
	if err != nil {
		return fmt.Errorf("failed to create snyk_dep_graph asset expression: %w", err)
	}

	startParams := testapi.StartTestParams{
		OrgID:   orgID.String(),
		Subject: ts,
	}

	// Instantiate the test client
	log.Println("Creating test client...")
	hlClient, err := testapi.NewTestClient(
		snykAPI(),
		testapi.Config{},
		testapi.WithHTTPClient(httpclient()),
	)
	if err != nil {
		return fmt.Errorf("failed to create test client: %w", err)
	}
	log.Println("Test client created.")

	// Begin the test
	log.Printf("Starting test for Org %s, Asset %s...", orgIDStr, assetID)
	handle, err := hlClient.StartTest(ctx, startParams)
	if err != nil {
		return fmt.Errorf("failed to start test: %w", err)
	}

	// Wait for test results either synchronously or asynchronously

	// --- option A: Synchronous wait ---
	// log.Println("Waiting synchronously for test completion...")
	// finalStatus, err := handle.Wait(ctx)
	// if err != nil {
	// 	return fmt.Errorf("test run failed: %w", err)
	// }
	// log.Println("Synchronous wait complete.")
	// processFinalStatus(finalStatus)
	// ---

	// --- option B: Asynchronous wait ---
	log.Println("Starting asynchronous test wait...")
	go handle.Wait(ctx) //nolint:errcheck // error is handled via handle.Result() afer Done() signals completion

	var finalStatus testapi.FinalStatus
	select {
	case <-handle.Done():
		log.Println("Asynchronous wait complete.")
		finalStatus, err = handle.Result()
		if err != nil {
			return fmt.Errorf("test polling failed: %w", err)
		}
	case <-time.After(3 * time.Minute):
		return fmt.Errorf("timed out waiting for test to complete")
	case <-ctx.Done():
		return fmt.Errorf("context canceled while polling: %w", ctx.Err())
	}
	// ---

	// Display overview of results
	processFinalStatus(finalStatus)

	// Now fetch and display findings
	// TODO: below uses the low-level API. Update to high-level functions.

	if finalStatus.State == string(v20241015defs.Errored) {
		log.Printf("Test finished with state 'errored'. Message: %s", finalStatus.Message)
		return fmt.Errorf("test execution failed: %s", finalStatus.Message)
	}

	if *finalStatus.Outcome == v20241015defs.Fail && finalStatus.TestID != nil {
		err = listAndPrintFindings(ctx, orgID, *finalStatus.TestID)
		if err != nil {
			log.Printf("Warning: test succeeded but failed to list findings: %v", err)
		}
	} else if *finalStatus.Outcome == v20241015defs.Pass {
		log.Println("Test succeeded.")
	}

	return nil
}

// processFinalStatus logs the details from the FinalStatus struct.
func processFinalStatus(status testapi.FinalStatus) {
	log.Println("--- Final Test Status ---")
	if status.TestID != nil {
		log.Printf("Test ID: %s", status.TestID.String())
	} else {
		log.Printf("Test ID: <nil>")
	}
	log.Printf("State:   %s", status.State)
	if status.Outcome != nil {
		log.Printf("Outcome: %s", *status.Outcome)
	} else {
		log.Printf("Outcome: <nil>")
	}
	if status.OutcomeReason != nil {
		log.Printf("Reason:  %s", *status.OutcomeReason)
	}
	if status.Message != "" {
		log.Printf("Message: %s", status.Message)
	}

	logJSON("Effective Summary:", status.EffectiveSummary)
	log.Println("-------------------------")
}

// Fetch and print first page of findings for a completed test.
// TODO: update to use high-level API.
func listAndPrintFindings(ctx context.Context, orgID uuid.UUID, testID uuid.UUID) error {
	log.Printf("Fetching findings for Test ID: %s, Org ID: %s", testID, orgID)

	req, err := v20241015defs.NewListFindingsRequest(
		snykAPI(), orgID, testID,
		&v20241015defs.ListFindingsParams{
			Version: "2024-10-15",
			Limit:   ptr(int8(100)),
		})
	if err != nil {
		return fmt.Errorf("error creating findings request: %w", err)
	}
	logRequest(req)

	resp, err := httpclient().Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("findings request failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("findings response status: %s", resp.Status)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d fetching findings", resp.StatusCode)
	}

	// Parse the successful response
	findingsResp, err := v20241015defs.ParseListFindingsResponse(resp)
	if err != nil {
		return fmt.Errorf("error parsing list findings response: %w", err)
	}

	if findingsResp.ApplicationvndApiJSON200 == nil {
		return fmt.Errorf("got 200 OK for findings but response body was nil")
	}

	findingsData := findingsResp.ApplicationvndApiJSON200.Data
	log.Printf("Found %d findings (first page):", len(findingsData))
	logJSON("Findings Data:", findingsData)

	return nil
}

func logRequest(r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
}

func logJSON(prefix string, v any) {
	if v == nil {
		log.Printf("%s <nil>", prefix)
		return
	}
	contents, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("%s Error marshaling to JSON: %v", prefix, err)
		return
	}
	if prefix != "" {
		log.Printf("%s\n%s", prefix, string(contents))
	} else {
		log.Println(string(contents))
	}
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}
