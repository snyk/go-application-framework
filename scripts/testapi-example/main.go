//nolint:goconst,gocritic // demo script
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"

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
		Transport: &retryRoundTripper{http.DefaultTransport},
	}
}

func relatedTestID(urlPath string) (*v20241015defs.TestIdParam, error) {
	// Return test UUID from a test response's related link, expected as:
	// "/orgs/<org_id>/tests/bf1638d7-5077-4383-aa40-a89d3405178b?version=2024-10-15"
	parts := strings.Split(urlPath, "/")
	for i, part := range parts {
		if part == "tests" && i+1 < len(parts) {
			uuidPart := parts[i+1]
			if queryIndex := strings.Index(uuidPart, "?"); queryIndex != -1 {
				uuidPart = uuidPart[:queryIndex]
			}

			uuid, err := uuid.Parse(uuidPart)
			if err != nil {
				return nil, fmt.Errorf("failed to extract test ID: %w", err)
			}

			return &uuid, nil
		}
	}
	return nil, fmt.Errorf("pattern '/tests/<uuid>' not found in '%s'", urlPath)
}

type retryRoundTripper struct{ http.RoundTripper }

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

func run() error { //nolint:gocyclo // chill it's a demo script
	orgID, err := orgUUID()
	if err != nil {
		return fmt.Errorf("failed to get org ID: %w", err)
	}

	assetID := uuid.New()

	if len(os.Args) != 2 {
		return fmt.Errorf("requires DepGraph filename as input")
	}

	// Load a depgraph file from input
	var contents []byte
	if strings.TrimSpace(os.Args[1]) != "-" {
		filepath := path.Clean(os.Args[1])
		fmt.Println("Loading DepGraph from file: ", filepath)
		contents, err = os.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("unable to load input file: %w", err)
		}
	}

	// We want only the depGraph field
	var depGraphStruct struct {
		DepGraph v20241015defs.IoSnykApiV1testdepgraphRequestDepGraph `json:"depGraph"`
	}

	// Wrap it with an envelope that tells the unified sdk how to transform it
	err = json.Unmarshal(contents, &depGraphStruct)
	if err != nil {
		return fmt.Errorf("unmarshal test data failed: %w", err)
	}
	ts := v20241015defs.TestSubjectCreate{}
	err = ts.FromDepGraphSubjectCreate(v20241015defs.DepGraphSubjectCreate{
		AssetId:     assetID,
		DepGraph:    depGraphStruct.DepGraph,
		SourceFiles: []string{"package.json"},
		Type:        v20241015defs.DepGraphSubjectCreateType("snyk_dep_graph"),
	})
	if err != nil {
		return fmt.Errorf("could not create asset: %w", err)
	}

	contents, err = json.Marshal(&v20241015defs.TestRequestBody{
		Data: v20241015defs.TestDataCreate{
			Attributes: v20241015defs.TestAttributesCreate{
				Subject: ts,
				Config: &v20241015defs.TestConfiguration{
					LocalPolicy: &v20241015defs.LocalPolicy{
						SeverityThreshold:      ptr(v20241015defs.SeverityMedium),
						SuppressPendingIgnores: false,
					},
				},
			},
			Type: v20241015defs.TestDataCreateTypeTests,
		},
	})
	if err != nil {
		return fmt.Errorf("could not jsonify test request: %w", err)
	}

	// Create a test
	req, err := v20241015defs.NewCreateTestRequestWithBody(
		snykAPI(), orgID,
		&v20241015defs.CreateTestParams{
			Version: "2024-10-15",
		},
		"application/vnd.api+json", bytes.NewBuffer(contents))
	if err != nil {
		return fmt.Errorf("unable to create test request: %w", err)
	}
	logRequest(req)
	req.Header.Set("Authorization", "token "+os.Getenv("SNYK_TOKEN"))

	resp, err := httpclient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		var responseBody []byte
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			responseBody = fmt.Appendf(nil, "Error reading response body: %v", err)
		}
		return fmt.Errorf("unexpected status code %d, response: %s", resp.StatusCode, string(responseBody))
	}
	log.Printf("HTTP %s", resp.Status)

	// Expect a 202 response
	parsedResp, err := v20241015defs.ParseCreateTestResponse(resp)
	if err != nil {
		return fmt.Errorf("unable to parse test response: %w", err)
	}
	parsedBody := parsedResp.ApplicationvndApiJSON202
	logJSON(parsedBody)

	// Poll the test to completion
	var testID *v20241015defs.TestIdParam = nil
	for testID == nil {
		fmt.Println("Polling for test result... ")

		req, err = v20241015defs.NewGetJobRequest(
			snykAPI(), orgID,
			parsedBody.Data.Id,
			&v20241015defs.GetJobParams{
				Version: "2024-10-15",
			})
		if err != nil {
			return fmt.Errorf("unable to create job request: %w", err)
		}
		logRequest(req)
		req.Header.Set("Authorization", "token "+os.Getenv("SNYK_TOKEN"))

		resp, err = httpclient().Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		log.Printf("HTTP %s", resp.Status)
		if resp.StatusCode == http.StatusNotFound {
			log.Printf("got 404... storage unsettled?")
			continue
		} else if resp.StatusCode == http.StatusOK {
			continue
		} else if resp.StatusCode != http.StatusSeeOther {
			return fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}

		// Expect a 303 response
		var jobResp *v20241015defs.GetJobResponse
		jobResp, err = v20241015defs.ParseGetJobResponse(resp)
		if err != nil {
			return fmt.Errorf("unable to parse get job response: %w", err)
		}
		jobRespBody := jobResp.ApplicationvndApiJSON303
		logJSON(jobRespBody)

		// extract test ID to fetch findings
		var relLink string
		relLink, err = jobRespBody.Links.Related.AsIoSnykApiCommonLinkString()
		if err != nil {
			return fmt.Errorf("failed to get related link: %w", err)
		}
		testID, err = relatedTestID(relLink)
		if err != nil {
			return fmt.Errorf("failed to extract test ID: %w", err)
		}

		log.Println("test is done")
	}

	fmt.Println("Relative TestID: ", *testID)

	// Get test results
	req, err = v20241015defs.NewGetTestRequest(
		snykAPI(), orgID, *testID,
		&v20241015defs.GetTestParams{
			Version: "2024-10-15",
		})
	if err != nil {
		return fmt.Errorf("unable to create test request: %w", err)
	}
	logRequest(req)
	req.Header.Set("Authorization", "token "+os.Getenv("SNYK_TOKEN"))

	resp, err = httpclient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			log.Printf("got 404... but test is done?")
			return fmt.Errorf("failed to get finished test")
		}
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// Expect a 200 response
	testResp, err := v20241015defs.ParseGetTestResponse(resp)
	if err != nil {
		return fmt.Errorf("unable to parse test response: %w", err)
	}
	testBody := testResp.ApplicationvndApiJSON200
	logJSON(testBody)

	if testBody.Data.Attributes.Outcome == nil {
		return fmt.Errorf("test completed with no outcome")
	}
	if testBody.Data.Attributes.Outcome.Result == v20241015defs.Pass {
		fmt.Println("passed with no findings")
		return nil
	}

	// Display the first page of findings

	req, err = v20241015defs.NewListFindingsRequest(
		snykAPI(), orgID, *testBody.Data.Id,
		&v20241015defs.ListFindingsParams{
			Version: "2024-10-15",
			Limit:   ptr(int8(100)),
		})
	if err != nil {
		return fmt.Errorf("errors creating findings request: %w", err)
	}

	logRequest(req)
	req.Header.Set("Authorization", "token "+os.Getenv("SNYK_TOKEN"))

	resp, err = httpclient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	findingsResp, err := v20241015defs.ParseListFindingsResponse(resp)
	if err != nil {
		fmt.Println("Error parsing list findings response: ", err)
	}
	findingsBody := findingsResp.ApplicationvndApiJSON200.Data

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	err = enc.Encode(&findingsBody)
	if err != nil {
		return fmt.Errorf("failed to parse findings: %w", err)
	}

	log.Printf("%d findings -- test complete", len(findingsBody))

	return nil
}

func logRequest(r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
}

func logJSON(v any) {
	contents, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Println(err)
	}
	log.Println(string(contents))
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}
