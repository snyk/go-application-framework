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
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling"
)

func ingestAttributes(body map[string]interface{}) map[string]interface{} {
	data, ok := body["data"].(map[string]interface{})
	if !ok {
		return nil
	}
	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return nil
	}
	return attributes
}

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

		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		AuthHeader: "token test-token",
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{
				EntityID: "project-1",
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
	assert.Equal(t, http.StatusCreated, result.HTTPStatus)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "token test-token", gotAuth)

	attributes := ingestAttributes(gotBody)
	require.NotNil(t, attributes)
	assert.Equal(t, "project-1", attributes["contributors_entity_id"])
	assert.Equal(t, "project", attributes["contributors_entity_type"])
}

func TestEmitContributorBilling_MultipleItems(t *testing.T) {
	t.Parallel()

	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		AuthHeader: "token test-token",
		Capability: contributorbilling.CapabilityIaC,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-a"},
			{EntityID: "project-b"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.Equal(t, 2, requestCount)
}

func TestEmitContributorBilling_SkipsEmptyItems(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
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

func TestEmitContributorBilling_SkipsMissingEntityID(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: ""},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonMissingEntityID, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_AllowsEmptyCapability(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.True(t, called)
}

func TestEmitContributorBilling_SkipsInvalidCapability(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: "osss",
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonInvalidCapability, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_SkipsMissingScopeID(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
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

func TestEmitContributorBilling_FiltersInvalidEntityIDs(t *testing.T) {
	t.Parallel()

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: ""},
			{EntityID: "project-a"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	attributes := ingestAttributes(gotBody)
	require.NotNil(t, attributes)
	assert.Equal(t, "project-a", attributes["contributors_entity_id"])
}

func TestEmitContributorBilling_MissingIngestURL(t *testing.T) {
	t.Parallel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
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
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            dir,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
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

func TestEmitContributorBilling_CompletesWhenParentContextAlreadyCanceled(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.True(t, called)
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

		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	items := []contributorbilling.BillingItem{
		{EntityID: "original-project"},
	}

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items:      items,
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	items[0].EntityID = "mutated-project"
	close(blockPost)

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	attributes := ingestAttributes(gotBody)
	require.NotNil(t, attributes)
	assert.Equal(t, "original-project", attributes["contributors_entity_id"])
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
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
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
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	start := time.Now()
	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Timeout:    20 * time.Millisecond,
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
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

func TestEmitContributorBilling_CompletesDespiteCanceledContextDuringSlowPOST(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.True(t, called)
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
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	logger := zerolog.Nop()
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityCode,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            repoPath,
		CollectContributors: true,
		Logger:              &logger,
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.NoError(t, result.ContributorCollectionErr)

	attributes := ingestAttributes(gotBody)
	require.NotNil(t, attributes)
	contributors, ok := attributes["contributors"].([]interface{})
	require.True(t, ok)
	require.Len(t, contributors, 2)

	byEmail := make(map[string]string)
	for _, raw := range contributors {
		contributor, ok := raw.(map[string]interface{})
		require.True(t, ok)
		email, ok := contributor["email"].(string)
		require.True(t, ok)
		commitDate, ok := contributor["commit_date"].(string)
		require.True(t, ok)
		byEmail[email] = commitDate
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
	var bodies []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &parsed))
		bodies = append(bodies, parsed)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityOSS,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            repoPath,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{
				EntityID: "project-prefilled",
				Contributors: []contributorbilling.Contributor{
					{Email: "prefilled@example.com", LatestCommitDate: prefilledWhen},
				},
			},
			{EntityID: "project-collected"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	require.Len(t, bodies, 2)

	byEntity := make(map[string][]interface{})
	for _, body := range bodies {
		attributes := ingestAttributes(body)
		require.NotNil(t, attributes)
		entityID, ok := attributes["contributors_entity_id"].(string)
		require.True(t, ok)
		itemContributors, ok := attributes["contributors"].([]interface{})
		require.True(t, ok)
		byEntity[entityID] = itemContributors
	}

	require.Len(t, byEntity["project-prefilled"], 1)
	prefilled, ok := byEntity["project-prefilled"][0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "prefilled@example.com", prefilled["email"])
	assert.Equal(t, prefilledWhen.Format(time.RFC3339), prefilled["commit_date"])

	require.Len(t, byEntity["project-collected"], 1)
	collected, ok := byEntity["project-collected"][0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "collected@example.com", collected["email"])
}

func TestEmitContributorBilling_DedupesContributorsByEmail(t *testing.T) {
	t.Parallel()

	older := time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 1, 20, 8, 0, 0, 0, time.UTC)
	otherWhen := time.Date(2026, 1, 15, 8, 0, 0, 0, time.UTC)

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{
				EntityID: "project-deduped",
				Contributors: []contributorbilling.Contributor{
					{Email: "alice@example.com", LatestCommitDate: older},
					{Email: "alice@example.com", LatestCommitDate: newer},
					{Email: "Alice@example.com", LatestCommitDate: otherWhen},
					{Email: "bob@example.com", LatestCommitDate: older},
				},
			},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	attributes := ingestAttributes(gotBody)
	require.NotNil(t, attributes)
	contributors, ok := attributes["contributors"].([]interface{})
	require.True(t, ok)
	require.Len(t, contributors, 3)

	byEmail := make(map[string]string)
	for _, raw := range contributors {
		contributor, ok := raw.(map[string]interface{})
		require.True(t, ok)
		email, ok := contributor["email"].(string)
		require.True(t, ok)
		commitDate, ok := contributor["commit_date"].(string)
		require.True(t, ok)
		byEmail[email] = commitDate
	}

	assert.Equal(t, newer.Format(time.RFC3339), byEmail["alice@example.com"])
	assert.Equal(t, otherWhen.Format(time.RFC3339), byEmail["Alice@example.com"])
	assert.Equal(t, older.Format(time.RFC3339), byEmail["bob@example.com"])
}

func TestEmitContributorBilling_CollectContributorsUsesItemRepoPath(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	defaultWhen := now.AddDate(0, 0, -5)
	itemWhen := now.AddDate(0, 0, -7)

	defaultRepo := initGitRepo(t, commitSpec{email: "default@example.com", when: defaultWhen})
	itemRepo := initGitRepo(t, commitSpec{email: "item@example.com", when: itemWhen})

	var bodies []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &parsed))
		bodies = append(bodies, parsed)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityIaC,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            defaultRepo,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-default"},
			{EntityID: "project-item", RepoPath: itemRepo},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	require.Len(t, bodies, 2)

	byEntity := make(map[string]string)
	for _, body := range bodies {
		attributes := ingestAttributes(body)
		require.NotNil(t, attributes)
		entityID, ok := attributes["contributors_entity_id"].(string)
		require.True(t, ok)
		contributors, ok := attributes["contributors"].([]interface{})
		require.True(t, ok)
		require.Len(t, contributors, 1)
		contributor, ok := contributors[0].(map[string]interface{})
		require.True(t, ok)
		email, ok := contributor["email"].(string)
		require.True(t, ok)
		byEntity[entityID] = email
	}

	assert.Equal(t, "default@example.com", byEntity["project-default"])
	assert.Equal(t, "item@example.com", byEntity["project-item"])
}

func TestEmitContributorBilling_CollectionFailureStillEmits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git"), []byte("corrupt"), 0o600))

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityOSS,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            dir,
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-1"},
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

func TestEmitContributorBilling_MultiItemContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &parsed))
		attributes := ingestAttributes(parsed)
		require.NotNil(t, attributes)

		entityID, ok := attributes["contributors_entity_id"].(string)
		require.True(t, ok)
		if entityID == "project-fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityIaC,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Items: []contributorbilling.BillingItem{
			{EntityID: "project-ok"},
			{EntityID: "project-fail"},
			{EntityID: "project-also-ok"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonHTTPError, result.FailReason)
	assert.Equal(t, 2, result.ItemsEmitted)
	assert.Equal(t, 1, result.ItemsFailed)
	assert.Equal(t, 3, int(requestCount.Load()))
}

func TestEmitContributorBilling_MultiItemPerItemTimeout(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &parsed))
		attributes := ingestAttributes(parsed)
		require.NotNil(t, attributes)

		entityID, ok := attributes["contributors_entity_id"].(string)
		require.True(t, ok)
		if entityID == "slow" {
			time.Sleep(200 * time.Millisecond)
		}

		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityIaC,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Timeout:    50 * time.Millisecond,
		Items: []contributorbilling.BillingItem{
			{EntityID: "slow"},
			{EntityID: "fast"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusFailed, result.Status)
	assert.Equal(t, contributorbilling.FailReasonTimeout, result.FailReason)
	assert.Equal(t, 1, result.ItemsEmitted)
	assert.Equal(t, 1, result.ItemsFailed)
	assert.Equal(t, 2, int(requestCount.Load()))
}

func TestEmitContributorBilling_CollectContributorsSurvivesChdirAfterEmit(t *testing.T) {
	t.Parallel()

	repoPath := initGitRepo(t, commitSpec{
		email: "dev@example.com",
		when:  time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
	})
	otherDir := t.TempDir()

	cwd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, os.Chdir(cwd))
	})

	require.NoError(t, os.Chdir(repoPath))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            ".",
		CollectContributors: true,
		Items: []contributorbilling.BillingItem{
			{EntityID: "22222222-2222-2222-2222-222222222222"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	require.NoError(t, os.Chdir(otherDir))

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.NoError(t, result.ContributorCollectionErr)
}
