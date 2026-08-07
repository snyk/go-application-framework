package capture_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
)

func TestCommandSession_sealAndNotifyFirstRecord(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	notified := false
	capture.RegisterFirstRecordHandler(func() {
		notified = true
	})

	bag := capture.OpenCommandSession("/tmp/repo")
	bag.Add(capture.Record{EntityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})

	capture.SealAndNotifyFirstRecord()
	assert.True(t, notified)
	assert.True(t, capture.IsSessionSealed())
	assert.Same(t, bag, capture.ActiveCapture())

	capture.SealAndNotifyFirstRecord()
	assert.True(t, capture.IsSessionSealed())
}

func TestCommandSession_sealedSessionKeepsActiveBag(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	bag := capture.OpenCommandSession("/tmp/first")
	bag.Add(capture.Record{EntityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	capture.SealAndNotifyFirstRecord()

	second := capture.EnsureCommandSession("/tmp/second")
	assert.Same(t, bag, second)
	assert.Equal(t, "/tmp/first", capture.SessionRepoPath())
	assert.True(t, capture.IsSessionSealed())
}

func TestCommandSession_openCloseLifecycle(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	bag := capture.OpenCommandSession("/tmp/repo")
	require.NotNil(t, bag)
	assert.Same(t, bag, capture.ActiveCapture())

	bag.Add(capture.Record{EntityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})

	closed, repoPath := capture.CloseCommandSession()
	assert.Same(t, bag, closed)
	assert.Equal(t, "/tmp/repo", repoPath)
	assert.Nil(t, capture.ActiveCapture())
}

func TestCommandSession_ensureDoesNotReplaceActiveSession(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	first := capture.EnsureCommandSession("/tmp/first")
	second := capture.EnsureCommandSession("/tmp/second")
	assert.Same(t, first, second)
	assert.Same(t, first, capture.ActiveCapture())

	first.Add(capture.Record{EntityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})

	closed, repoPath := capture.CloseCommandSession()
	assert.Same(t, first, closed)
	assert.Equal(t, "/tmp/first", repoPath)
}
