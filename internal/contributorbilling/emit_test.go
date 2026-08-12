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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
			Contributors: []contributorbilling.Contributor{
				{
					Email:            "dev@example.com",
					LatestCommitDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
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
		Item:       contributorbilling.BillingItem{},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonMissingEntityID, result.SkipReason)
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
		Item: contributorbilling.BillingItem{
			EntityID: "",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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

func TestEmitContributorBilling_SkipsInvalidEntityType(t *testing.T) {
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
		Item: contributorbilling.BillingItem{
			EntityID:   "project-1",
			EntityType: "invalid-type",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonInvalidEntityType, result.SkipReason)
	assert.False(t, called)
}

func TestEmitContributorBilling_TrimsEntityTypeWhitespace(t *testing.T) {
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
		Item: contributorbilling.BillingItem{
			EntityID:   "project-1",
			EntityType: "  target  ",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	attributes := ingestAttributes(gotBody)
	require.NotNil(t, attributes)
	assert.Equal(t, "target", attributes["contributors_entity_type"])
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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

func TestEmitContributorBilling_MissingIngestURL(t *testing.T) {
	t.Parallel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.True(t, called)
}

func TestEmitContributorBilling_CopiesItem(t *testing.T) {
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

	item := contributorbilling.BillingItem{
		EntityID: "original-project",
	}

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Item:       item,
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	item.EntityID = "mutated-project"
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
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
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityOSS,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		RepoPath:            repoPath,
		CollectContributors: true,
		Item: contributorbilling.BillingItem{
			EntityID: "project-prefilled",
			Contributors: []contributorbilling.Contributor{
				{Email: "prefilled@example.com", LatestCommitDate: prefilledWhen},
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
	require.Len(t, contributors, 1)

	prefilled, ok := contributors[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "prefilled@example.com", prefilled["email"])
	assert.Equal(t, prefilledWhen.Format(time.RFC3339), prefilled["commit_date"])
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-deduped",
			Contributors: []contributorbilling.Contributor{
				{Email: "alice@example.com", LatestCommitDate: older},
				{Email: "alice@example.com", LatestCommitDate: newer},
				{Email: "Alice@example.com", LatestCommitDate: otherWhen},
				{Email: "bob@example.com", LatestCommitDate: older},
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

	assert.Equal(t, newer.Format(time.RFC3339), byEmail["alice@example.com"])
	assert.Equal(t, older.Format(time.RFC3339), byEmail["bob@example.com"])
}

func TestEmitContributorBilling_PreservesContributorOrder(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)

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
		Item: contributorbilling.BillingItem{
			EntityID: "project-ordered",
			Contributors: []contributorbilling.Contributor{
				{Email: "zebra@example.com", LatestCommitDate: when},
				{Email: "alice@example.com", LatestCommitDate: when},
				{Email: "bob@example.com", LatestCommitDate: when},
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

	emails := make([]string, 0, len(contributors))
	for _, raw := range contributors {
		contributor, ok := raw.(map[string]interface{})
		require.True(t, ok)
		email, ok := contributor["email"].(string)
		require.True(t, ok)
		emails = append(emails, email)
	}

	assert.Equal(t, []string{"zebra@example.com", "alice@example.com", "bob@example.com"}, emails)
}

func TestEmitContributorBilling_CollectContributorsUsesItemRepoPath(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	itemWhen := now.AddDate(0, 0, -7)

	itemRepo := initGitRepo(t, commitSpec{email: "item@example.com", when: itemWhen})

	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &parsed))
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient:          server.Client(),
		IngestURL:           server.URL,
		Capability:          contributorbilling.CapabilityIaC,
		ScopeID:             "11111111-1111-1111-1111-111111111111",
		CollectContributors: true,
		Item: contributorbilling.BillingItem{
			EntityID: "project-item",
			RepoPath: itemRepo,
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
	require.Len(t, contributors, 1)
	contributor, ok := contributors[0].(map[string]interface{})
	require.True(t, ok)
	email, ok := contributor["email"].(string)
	require.True(t, ok)
	assert.Equal(t, "item@example.com", email)
}

func TestEmitContributorBilling_CollectionFailureSkipsWhenEmpty(t *testing.T) {
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
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.False(t, called)
	assert.Equal(t, contributorbilling.ResultStatusSkipped, result.Status)
	assert.Equal(t, contributorbilling.SkipReasonEmptyContributors, result.SkipReason)
	require.Error(t, result.ContributorCollectionErr)
}

func TestEmitContributorBilling_CollectContributorsSurvivesChdirAfterEmit(t *testing.T) {
	repoPath := initGitRepo(t, commitSpec{
		email: "dev@example.com",
		when:  time.Now().AddDate(0, 0, -5),  // within 90-day window
	})

	t.Chdir(repoPath)

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
		Item: contributorbilling.BillingItem{
			EntityID: "22222222-2222-2222-2222-222222222222",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
	assert.NoError(t, result.ContributorCollectionErr)
}
