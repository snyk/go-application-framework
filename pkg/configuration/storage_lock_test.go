package configuration_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Two goroutines calling Lock/Unlock on the same Storage must never run their
// locked sections concurrently. gofrs/flock's TryLockContext only guards against
// other processes; within one process, a second caller on the same *flock.Flock
// is granted the lock immediately once the first caller already holds it.
func Test_JsonStorage_Lock_ProvidesInProcessMutualExclusion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.json")
	storage := configuration.NewJsonStorage(path)

	var active int32
	var overlapped atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)

	critical := func() {
		defer wg.Done()
		err := storage.Lock(context.Background(), time.Millisecond)
		if !assert.NoError(t, err) {
			return
		}
		defer func() { _ = storage.Unlock() }() //nolint:errcheck // unlock errors are ignored; nothing actionable can be done with a failed unlock here

		if atomic.AddInt32(&active, 1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&active, -1)
	}

	go critical()
	go critical()
	wg.Wait()

	assert.False(t, overlapped.Load(), "two goroutines executed the locked section concurrently")
}

// A Lock call that fails (here, because another holder already has the OS-level
// file lock) must not leave the in-process gate held - otherwise every later
// Lock call on this Storage would block forever.
func Test_JsonStorage_Lock_FailedAcquisitionDoesNotLeakInProcessGate(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.json")
	storage := configuration.NewJsonStorage(path)

	external := flock.New(path + ".lock")
	locked, err := external.TryLock()
	require.NoError(t, err)
	require.True(t, locked)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.Error(t, storage.Lock(ctx, time.Millisecond), "lock should fail while another holder has the OS-level file lock")

	require.NoError(t, external.Unlock())

	require.NoError(t, storage.Lock(context.Background(), time.Millisecond), "a prior failed acquisition must not leave the in-process gate held")
	require.NoError(t, storage.Unlock())
}

// Unlock is called defensively in several call sites (e.g. via defer) even when
// the preceding Lock may not have succeeded, so it must stay safe without a
// matching Lock, both before any Lock call and after a matched pair.
func Test_JsonStorage_Unlock_WithoutMatchingLockIsSafe(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.json")
	storage := configuration.NewJsonStorage(path)

	assert.NoError(t, storage.Unlock(), "unlocking without a prior successful Lock must be a safe no-op")

	assert.NoError(t, storage.Lock(context.Background(), time.Millisecond))
	assert.NoError(t, storage.Unlock())

	assert.NoError(t, storage.Unlock(), "an extra Unlock after a matched Lock/Unlock pair must also stay safe")
}

// A caller waiting on the in-process gate must give up when its context expires,
// not just when the OS-level file lock is contended.
func Test_JsonStorage_Lock_HonorsContextTimeoutWhileWaitingInProcess(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.json")
	storage := configuration.NewJsonStorage(path)

	require.NoError(t, storage.Lock(context.Background(), time.Millisecond))
	defer func() { _ = storage.Unlock() }() //nolint:errcheck // unlock errors are ignored; nothing actionable can be done with a failed unlock here

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := storage.Lock(ctx, time.Millisecond)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 5*time.Second, "Lock must return once ctx expires, not hang waiting on the in-process gate")
}
