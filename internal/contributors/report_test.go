package contributors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/metrics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func TestReport_RecordsEmissionWithContributorCount(t *testing.T) {
	var posted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted = true
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	s := capturedSink(t)
	recorder := metrics.NewRecorderFake()
	engine := newTestEngine(t, testConfig(server.URL, testOrgID.String(), newRepoWithCommit(t)), server.Client())

	report(t.Context(), engine, s, recorder)

	assert.True(t, posted, "an emission must reach the ingest API")
	assert.Equal(t, string(resultEmitted), recorder.StringValues[analyticsKeyResult])
	assert.Equal(t, 1, recorder.IntValues[analyticsKeyCount])
}

// The count is meaningless before collection finishes, so it must be absent
// rather than reported as a misleading zero.
func TestReport_OmitsContributorCountWhenNothingWasCollected(t *testing.T) {
	s := capturedSink(t)
	recorder := metrics.NewRecorderFake()
	engine := newTestEngine(t, testConfig("https://api.snyk.io", "not-a-uuid", t.TempDir()), http.DefaultClient)

	report(t.Context(), engine, s, recorder)

	require.Equal(t, string(resultOrgIDInvalid), recorder.StringValues[analyticsKeyResult])
	assert.NotContains(t, recorder.IntValues, analyticsKeyCount)
}

func TestReport_RecordsWhyNothingWasCaptured(t *testing.T) {
	tests := map[string]struct {
		reason MissReason
		want   collectionResult
	}{
		"no request worth capturing from": {reason: MissNone, want: resultNoRelevantRequest},
		"error response":                  {reason: MissErrorStatus, want: resultCaptureErrorStatus},
		"oversized body":                  {reason: MissBodyTooLarge, want: resultCaptureBodyTooLarge},
		"unreadable body":                 {reason: MissBodyUnreadable, want: resultCaptureBodyUnreadable},
		"no entity in body":               {reason: MissNoEntity, want: resultCaptureNoEntity},
		"panic during capture":            {reason: MissPanic, want: resultCapturePanic},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Sink{}
			if tc.reason != MissNone {
				s.RecordMiss(tc.reason)
			}
			recorder := metrics.NewRecorderFake()
			engine := newTestEngine(t, testConfig("https://api.snyk.io", testOrgID.String(), t.TempDir()), http.DefaultClient)

			report(t.Context(), engine, s, recorder)

			assert.Equal(t, string(tc.want), recorder.StringValues[analyticsKeyResult])
			assert.NotContains(t, recorder.IntValues, analyticsKeyCount)
		})
	}
}

func TestReport_RecordsWhyACapturedEntityWasNotEmitted(t *testing.T) {
	rejectingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	t.Cleanup(rejectingServer.Close)

	tests := map[string]struct {
		apiURL   string
		orgID    string
		inputDir string
		canceled bool
		want     collectionResult
	}{
		"organization is not a UUID": {
			apiURL: "https://api.snyk.io", orgID: "acme-corp", inputDir: newRepoWithCommit(t),
			want: resultOrgIDInvalid,
		},
		"no directory to collect from": {
			apiURL: "https://api.snyk.io", orgID: testOrgID.String(), inputDir: "",
			want: resultNoInputDirectory,
		},
		"API URL is unusable": {
			apiURL: "not-a-url", orgID: testOrgID.String(), inputDir: newRepoWithCommit(t),
			want: resultEmitterInitFailed,
		},
		"directory is not a repository": {
			apiURL: "https://api.snyk.io", orgID: testOrgID.String(), inputDir: t.TempDir(),
			want: resultNotAGitRepo,
		},
		"repository has no contributors in the window": {
			apiURL: "https://api.snyk.io", orgID: testOrgID.String(), inputDir: newRepoWithOldCommit(t),
			want: resultNoContributors,
		},
		"ingest rejects the submission": {
			apiURL: rejectingServer.URL, orgID: testOrgID.String(), inputDir: newRepoWithCommit(t),
			want: resultSubmitFailed,
		},
		"invocation was canceled": {
			apiURL: "https://api.snyk.io", orgID: testOrgID.String(), inputDir: newRepoWithCommit(t),
			canceled: true, want: resultTimedOut,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			if tc.canceled {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}

			s := capturedSink(t)
			recorder := metrics.NewRecorderFake()
			engine := newTestEngine(t, testConfig(tc.apiURL, tc.orgID, tc.inputDir), rejectingServer.Client())

			report(ctx, engine, s, recorder)

			assert.Equal(t, string(tc.want), recorder.StringValues[analyticsKeyResult])
			assert.NotContains(t, recorder.IntValues, analyticsKeyCount)
		})
	}
}

// A hook abandoned at POST_INVOKE_HOOK_TIMEOUT never reaches its final write, so
// the outcome recorded before any work starts is the one that survives.
func TestReport_RecordsTheTimeoutBeforeDoingAnyWork(t *testing.T) {
	s := capturedSink(t)
	recorder := &sequenceRecorder{}
	engine := newTestEngine(t, testConfig("https://api.snyk.io", testOrgID.String(), t.TempDir()), http.DefaultClient)

	report(t.Context(), engine, s, recorder)

	require.Len(t, recorder.results, 2)
	assert.Equal(t, string(resultTimedOut), recorder.results[0])
	assert.Equal(t, string(resultNotAGitRepo), recorder.results[1])
}

func TestReport_KeepsTheOutcomeOfTheInvocationThatReported(t *testing.T) {
	var posts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	s := capturedSink(t)
	recorder := metrics.NewRecorderFake()
	engine := newTestEngine(t, testConfig(server.URL, testOrgID.String(), newRepoWithCommit(t)), server.Client())

	for range 3 {
		report(t.Context(), engine, s, recorder)
	}

	assert.Equal(t, 1, posts, "contributors must be emitted once, not once per invocation")
	assert.Equal(t, string(resultEmitted), recorder.StringValues[analyticsKeyResult])
	assert.Equal(t, 1, recorder.IntValues[analyticsKeyCount])
}

func TestReport_StillReportsACaptureMadeAfterAnEarlierInvocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	s := &Sink{}
	recorder := metrics.NewRecorderFake()
	engine := newTestEngine(t, testConfig(server.URL, testOrgID.String(), newRepoWithCommit(t)), server.Client())

	report(t.Context(), engine, s, recorder)
	require.Equal(t, string(resultNoRelevantRequest), recorder.StringValues[analyticsKeyResult])

	s.RecordEntity(EntityTypeProject, "22222222-2222-2222-2222-222222222222")
	report(t.Context(), engine, s, recorder)

	assert.Equal(t, string(resultEmitted), recorder.StringValues[analyticsKeyResult])
	assert.Equal(t, 1, recorder.IntValues[analyticsKeyCount])
}

func TestEmitResult_MapsFailuresThatEndToEndTestsCannotProvoke(t *testing.T) {
	tests := map[string]struct {
		err  error
		want collectionResult
	}{
		"unreadable repository": {
			err:  fmt.Errorf("%w: %w", ErrCollect, errors.New("read commits")),
			want: resultCollectFailed,
		},
		// Cancelation surfaces wrapped in whichever stage was interrupted, so it
		// has to outrank that stage rather than be hidden by it.
		"cancelation during collection": {
			err:  fmt.Errorf("%w: %w", ErrCollect, context.Canceled),
			want: resultTimedOut,
		},
		"cancelation during submission": {
			err:  fmt.Errorf("%w: %w", ErrSubmit, context.DeadlineExceeded),
			want: resultTimedOut,
		},
		// A malformed item cannot come from the capture middleware, but it is
		// rejected in place of the submission it would have been sent in.
		"malformed item": {
			err:  errors.New("unsupported entity type"),
			want: resultSubmitFailed,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, emitResult(tc.err))
		})
	}
}

func TestSink_PrefersACapturedEntityOverAnyMiss(t *testing.T) {
	s := &Sink{}
	s.RecordMiss(MissErrorStatus)
	s.RecordEntity(EntityTypeProject, "22222222-2222-2222-2222-222222222222")

	item, alreadyTaken := s.take()
	require.NotNil(t, item)
	assert.False(t, alreadyTaken)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", item.EntityID)
}

func TestSink_DistinguishesAnAlreadyTakenCaptureFromNoCapture(t *testing.T) {
	empty := &Sink{}
	item, alreadyTaken := empty.take()
	assert.Nil(t, item)
	assert.False(t, alreadyTaken)

	s := capturedSink(t)
	_, alreadyTaken = s.take()
	require.False(t, alreadyTaken)

	item, alreadyTaken = s.take()
	assert.Nil(t, item)
	assert.True(t, alreadyTaken)
}

func TestSink_KeepsTheFirstMissReported(t *testing.T) {
	s := &Sink{}
	s.RecordMiss(MissErrorStatus)
	s.RecordMiss(MissPanic)

	assert.Equal(t, MissErrorStatus, s.miss())
}

// sequenceRecorder keeps every outcome written, in order, which the shared
// recorder fake cannot express because it holds only the latest value per key.
type sequenceRecorder struct {
	results []string
	counts  []int
}

func (r *sequenceRecorder) AddExtensionStringValue(key string, value string) {
	if key == analyticsKeyResult {
		r.results = append(r.results, value)
	}
}

func (r *sequenceRecorder) AddExtensionIntegerValue(key string, value int) {
	if key == analyticsKeyCount {
		r.counts = append(r.counts, value)
	}
}

func (r *sequenceRecorder) AddExtensionBoolValue(string, bool) {}

// capturedSink returns a sink holding an entity, as the capture middleware would
// have left it.
func capturedSink(t *testing.T) *Sink {
	t.Helper()

	s := &Sink{}
	s.RecordEntity(EntityTypeProject, "22222222-2222-2222-2222-222222222222")
	return s
}

func testConfig(apiURL, orgID, inputDir string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, apiURL)
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(configuration.INPUT_DIRECTORY, []string{inputDir})
	return config
}

func newTestEngine(t *testing.T, config configuration.Configuration, client *http.Client) *mocks.MockEngine {
	t.Helper()

	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()

	network := mocks.NewMockNetworkAccess(ctrl)
	network.EXPECT().GetHttpClient().Return(client).AnyTimes()

	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetLogger().Return(&logger).AnyTimes()
	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	engine.EXPECT().GetNetworkAccess().Return(network).AnyTimes()
	return engine
}

// newRepoWithCommit returns a repository with one commit authored now, so it has
// exactly one contributor in the window.
func newRepoWithCommit(t *testing.T) string {
	t.Helper()

	return newRepo(t, time.Now())
}

// newRepoWithOldCommit returns a repository whose only commit predates the
// contributor window.
func newRepoWithOldCommit(t *testing.T) string {
	t.Helper()

	return newRepo(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
}

func newRepo(t *testing.T, when time.Time) string {
	t.Helper()

	dir := t.TempDir()
	home := t.TempDir()

	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	env = append(env,
		"HOME="+home,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Alice",
		"GIT_AUTHOR_EMAIL=alice@example.com",
		"GIT_AUTHOR_DATE="+when.Format(time.RFC3339),
		"GIT_COMMITTER_NAME=Alice",
		"GIT_COMMITTER_EMAIL=alice@example.com",
		"GIT_COMMITTER_DATE="+when.Format(time.RFC3339),
	)

	git := func(args ...string) {
		t.Helper()

		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %s: %s", strings.Join(args, " "), out)
	}

	git("init", "--initial-branch=main", ".")
	git("commit", "--allow-empty", "-m", "a commit")
	return dir
}
