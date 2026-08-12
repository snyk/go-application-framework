package contributors_ingest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"
)

var (
	testOrgID    = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	testEntityID = "22222222-2222-2222-2222-222222222222"

	testContributors = []contributors_ingest.Contributor{
		{Email: "alice@example.com", CommitDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)},
		{Email: "bob@example.com", CommitDate: time.Date(2026, 1, 10, 8, 30, 0, 0, time.UTC)},
	}
)

func TestCreateContributingDevs_SendsGoldenPayload(t *testing.T) {
	baseURL, httpClient, got := startServer(t, http.StatusCreated)

	client, err := contributors_ingest.NewClient(httpClient, baseURL, nil)
	require.NoError(t, err)

	err = client.SubmitContributors(
		t.Context(),
		testOrgID,
		contributors_ingest.EntityTypeProject,
		testEntityID,
		testContributors,
	)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/hidden/orgs/"+testOrgID.String()+"/contributing_devs", got.path)
	assert.Equal(t, "2024-10-15", got.query)
	assert.Equal(t, "application/vnd.api+json", got.header.Get("Content-Type"))

	golden, err := os.ReadFile("testdata/golden_ingest_payload.json")
	require.NoError(t, err)
	assert.JSONEq(t, string(golden), string(got.body))
}

func TestCreateContributingDevs_SendsEmptyArrayNotNull(t *testing.T) {
	baseURL, httpClient, got := startServer(t, http.StatusCreated)

	client, err := contributors_ingest.NewClient(httpClient, baseURL, nil)
	require.NoError(t, err)

	require.NoError(t, client.SubmitContributors(
		t.Context(), testOrgID, contributors_ingest.EntityTypeTarget, testEntityID, nil,
	))

	var body struct {
		Data struct {
			Attributes struct {
				Contributors *[]any `json:"contributors"`
				EntityType   string `json:"contributors_entity_type"`
			} `json:"attributes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(got.body, &body))

	require.NotNil(t, body.Data.Attributes.Contributors, "a null contributors field is rejected by the API")
	assert.Empty(t, *body.Data.Attributes.Contributors)
	assert.Equal(t, "target", body.Data.Attributes.EntityType)
}

func TestCreateContributingDevs_ErrorsOnUnexpectedStatus(t *testing.T) {
	// Only statuses the client does not retry; retried ones are covered in retry_test.go.
	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			baseURL, httpClient, _ := startServer(t, status)

			client, err := contributors_ingest.NewClient(httpClient, baseURL, nil)
			require.NoError(t, err)

			err = client.SubmitContributors(
				t.Context(), testOrgID, contributors_ingest.EntityTypeProject, testEntityID, testContributors,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), strconv.Itoa(status))
		})
	}
}

func TestCreateContributingDevs_ErrorsWhenServerUnreachable(t *testing.T) {
	client, err := contributors_ingest.NewClient(http.DefaultClient, "http://127.0.0.1:1", nil)
	require.NoError(t, err)

	err = client.SubmitContributors(
		t.Context(), testOrgID, contributors_ingest.EntityTypeProject, testEntityID, testContributors,
	)
	assert.Error(t, err)
}

func TestCreateContributingDevs_PreservesBaseURLPathPrefix(t *testing.T) {
	baseURL, httpClient, got := startServer(t, http.StatusCreated)

	client, err := contributors_ingest.NewClient(httpClient, baseURL+"/gateway/v1", nil)
	require.NoError(t, err)

	require.NoError(t, client.SubmitContributors(
		t.Context(), testOrgID, contributors_ingest.EntityTypeRevision, testEntityID, testContributors,
	))

	assert.Equal(t, "/gateway/v1/hidden/orgs/"+testOrgID.String()+"/contributing_devs", got.path)
}

func TestCreateContributingDevs_ConvertsCommitDatesToUTC(t *testing.T) {
	baseURL, httpClient, got := startServer(t, http.StatusCreated)

	client, err := contributors_ingest.NewClient(httpClient, baseURL, nil)
	require.NoError(t, err)

	tokyo, err := time.LoadLocation("Asia/Tokyo")
	require.NoError(t, err)

	require.NoError(t, client.SubmitContributors(
		t.Context(), testOrgID, contributors_ingest.EntityTypeProject, testEntityID,
		[]contributors_ingest.Contributor{
			{Email: "kenji@example.com", CommitDate: time.Date(2026, 1, 15, 21, 0, 0, 0, tokyo)},
		},
	))

	assert.Contains(t, string(got.body), `"commit_date":"2026-01-15T12:00:00Z"`)
}

func TestNewClient_RejectsUnusableBaseURL(t *testing.T) {
	for name, baseURL := range map[string]string{
		"empty":       "",
		"no scheme":   "api.snyk.io",
		"no host":     "https://",
		"unparseable": "://nope",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := contributors_ingest.NewClient(http.DefaultClient, baseURL, nil)
			assert.Error(t, err)
		})
	}
}

func TestEntityType_Valid(t *testing.T) {
	for _, valid := range []contributors_ingest.EntityType{
		contributors_ingest.EntityTypeProject,
		contributors_ingest.EntityTypeTarget,
		contributors_ingest.EntityTypeRevision,
	} {
		assert.True(t, valid.Valid(), valid)
	}

	for _, invalid := range []contributors_ingest.EntityType{"", "Project", "org", "repo"} {
		assert.False(t, invalid.Valid(), invalid)
	}
}

// capturedRequest holds what the test server saw.
type capturedRequest struct {
	method string
	url    string
	path   string
	query  string
	header http.Header
	body   []byte
}

// startServer returns a server replying with status, and the request it captured.
func startServer(t *testing.T, status int) (baseURL string, client *http.Client, got *capturedRequest) {
	t.Helper()

	got = &capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		got.method = r.Method
		got.url = r.URL.String()
		got.path = r.URL.Path
		got.query = r.URL.Query().Get("version")
		got.header = r.Header.Clone()
		got.body = body

		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)

	return server.URL, server.Client(), got
}
