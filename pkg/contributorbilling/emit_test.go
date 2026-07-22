package contributorbilling_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/contributorbilling"
)

func waitForResult(t *testing.T, ch <-chan contributorbilling.Result) contributorbilling.Result {
	t.Helper()

	select {
	case result := <-ch:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for emit result")
		return contributorbilling.Result{}
	}
}

func TestEmitContributorBilling_Success(t *testing.T) {
	t.Parallel()

	var (
		mu        sync.Mutex
		gotBody   map[string]interface{}
		gotAuth   string
		gotMethod string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))

		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL + contributorbilling.DefaultIngestPath,
		AuthHeader: "token test-token",
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{
				ProjectID: "project-1",
				Contributors: []contributorbilling.Contributor{
					{
						Email:            "dev@example.com",
						LatestCommitDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
					},
				},
			},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.Equal(t, http.StatusAccepted, result.HTTPStatus)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "token test-token", gotAuth)
	assert.Equal(t, "cli", gotBody["source"])
	assert.Equal(t, "oss", gotBody["capability"])
}

func TestEmitContributorBilling_MultipleItems(t *testing.T) {
	t.Parallel()

	var itemCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var payload struct {
			Items []json.RawMessage `json:"items"`
		}
		require.NoError(t, json.Unmarshal(body, &payload))
		itemCount = len(payload.Items)

		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		AuthHeader: "token test-token",
		Capability: contributorbilling.CapabilityIaC,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-a"},
			{ProjectID: "project-b"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.Equal(t, 2, itemCount)
}

func TestEmitContributorBilling_SkipsEmptyItems(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items:      nil,
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonEmptyItems, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_SkipsMissingProjectID(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: ""},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonMissingProjectID, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_SkipsMissingCapability(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonMissingCapability, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_SkipsMissingScopeID(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonMissingScopeID, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_FiltersInvalidProjectIDs(t *testing.T) {
	t.Parallel()

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: ""},
			{ProjectID: "project-a"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	items, ok := gotBody["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)

	firstItem, ok := items[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "project-a", firstItem["project_id"])
}

func TestEmitContributorBilling_MissingIngestURL(t *testing.T) {
	t.Parallel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonMissingIngestURL, result.FailReason)
	require.Error(t, result.Err)
}

func TestEmitContributorBilling_MissingIngestURLSkipsCollection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git"), []byte("corrupt"), 0o600))

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		Capability:          contributorbilling.CapabilityOSS,
		ScopeID:             "org-uuid",
		RepoPath:            dir,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonMissingIngestURL, result.FailReason)
	assert.NoError(t, result.ContributorCollectionErr)
}

func TestEmitContributorBilling_ContextCanceledBeforeEmit(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonCanceled, result.FailReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_CopiesItems(t *testing.T) {
	t.Parallel()

	blockPost := make(chan struct{})
	var gotBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockPost

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))

		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	items := []contributorbilling.BillingItem{
		{ProjectID: "original-project"},
	}

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items:      items,
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	items[0].ProjectID = "mutated-project"
	close(blockPost)

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	payloadItems, ok := gotBody["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, payloadItems, 1)

	firstItem, ok := payloadItems[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "original-project", firstItem["project_id"])
}

func TestEmitContributorBilling_HTTPFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonHTTPError, result.FailReason)
	assert.Equal(t, http.StatusInternalServerError, result.HTTPStatus)
	require.Error(t, result.Err)
	assert.Contains(t, result.Err.Error(), "500")
}

func TestEmitContributorBilling_TimeoutDoesNotBlockCaller(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	start := time.Now()
	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Timeout:    20 * time.Millisecond,
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	elapsed := time.Since(start)
	assert.Less(t, elapsed, 50*time.Millisecond)

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonTimeout, result.FailReason)
}

func TestEmitContributorBilling_ContextCanceled(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonCanceled, result.FailReason)
}

func TestEmitContributorBilling_CollectContributors(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	aliceWhen := now.AddDate(0, 0, -5)
	bobWhen := now.AddDate(0, 0, -7)
	repoPath := initGitRepo(t,
		commitSpec{email: "alice@example.com", when: aliceWhen},
		commitSpec{email: "bob@example.com", when: bobWhen},
	)

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	logger := zerolog.Nop()
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityCode,
		ScopeID:             "org-uuid",
		RepoPath:            repoPath,
		CollectContributors: true,
		Logger:              &logger,
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.NoError(t, result.ContributorCollectionErr)

	items, ok := gotBody["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)

	firstItem, ok := items[0].(map[string]interface{})
	require.True(t, ok)
	contributors, ok := firstItem["contributors"].([]interface{})
	require.True(t, ok)
	require.Len(t, contributors, 2)

	byEmail := make(map[string]string)
	for _, raw := range contributors {
		contributor, ok := raw.(map[string]interface{})
		require.True(t, ok)
		email, ok := contributor["email"].(string)
		require.True(t, ok)
		latestCommitDate, ok := contributor["latest_commit_date"].(string)
		require.True(t, ok)
		byEmail[email] = latestCommitDate
	}

	assert.Equal(t, aliceWhen.Format(time.RFC3339), byEmail["alice@example.com"])
	assert.Equal(t, bobWhen.Format(time.RFC3339), byEmail["bob@example.com"])
}

func TestEmitContributorBilling_CollectContributorsPreservesPrefilled(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	repoPath := initGitRepo(t,
		commitSpec{email: "collected@example.com", when: now.AddDate(0, 0, -5)},
	)

	prefilledWhen := time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC)
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityOSS,
		ScopeID:             "org-uuid",
		RepoPath:            repoPath,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{
				ProjectID: "project-prefilled",
				Contributors: []contributorbilling.Contributor{
					{Email: "prefilled@example.com", LatestCommitDate: prefilledWhen},
				},
			},
			{ProjectID: "project-collected"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	items, ok := gotBody["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 2)

	byProject := make(map[string][]interface{})
	for _, raw := range items {
		item, itemOK := raw.(map[string]interface{})
		require.True(t, itemOK)
		projectID, projectOK := item["project_id"].(string)
		require.True(t, projectOK)
		itemContributors, contributorsOK := item["contributors"].([]interface{})
		require.True(t, contributorsOK)
		byProject[projectID] = itemContributors
	}

	require.Len(t, byProject["project-prefilled"], 1)
	prefilled, ok := byProject["project-prefilled"][0].(map[string]interface{})
	require.True(t, ok)
	prefilledEmail, ok := prefilled["email"].(string)
	require.True(t, ok)
	prefilledDate, ok := prefilled["latest_commit_date"].(string)
	require.True(t, ok)
	assert.Equal(t, "prefilled@example.com", prefilledEmail)
	assert.Equal(t, prefilledWhen.Format(time.RFC3339), prefilledDate)

	require.Len(t, byProject["project-collected"], 1)
	collected, ok := byProject["project-collected"][0].(map[string]interface{})
	require.True(t, ok)
	collectedEmail, ok := collected["email"].(string)
	require.True(t, ok)
	assert.Equal(t, "collected@example.com", collectedEmail)
}

func TestEmitContributorBilling_CollectContributorsUsesItemRepoPath(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	defaultWhen := now.AddDate(0, 0, -5)
	itemWhen := now.AddDate(0, 0, -7)

	defaultRepo := initGitRepo(t, commitSpec{email: "default@example.com", when: defaultWhen})
	itemRepo := initGitRepo(t, commitSpec{email: "item@example.com", when: itemWhen})

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityIaC,
		ScopeID:             "org-uuid",
		RepoPath:            defaultRepo,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-default"},
			{ProjectID: "project-item", RepoPath: itemRepo},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	items, ok := gotBody["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 2)

	byProject := make(map[string]string)
	for _, raw := range items {
		item, itemOK := raw.(map[string]interface{})
		require.True(t, itemOK)
		itemContributors, contributorsOK := item["contributors"].([]interface{})
		require.True(t, contributorsOK)
		require.Len(t, itemContributors, 1)
		contributor, contributorOK := itemContributors[0].(map[string]interface{})
		require.True(t, contributorOK)
		projectID, projectOK := item["project_id"].(string)
		require.True(t, projectOK)
		email, emailOK := contributor["email"].(string)
		require.True(t, emailOK)
		byProject[projectID] = email
	}

	assert.Equal(t, "default@example.com", byProject["project-default"])
	assert.Equal(t, "item@example.com", byProject["project-item"])
}

func TestEmitContributorBilling_CollectionFailureStillEmits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git"), []byte("corrupt"), 0o600))

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityOSS,
		ScopeID:             "org-uuid",
		RepoPath:            dir,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{ProjectID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.True(t, called)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	require.Error(t, result.ContributorCollectionErr)
}
