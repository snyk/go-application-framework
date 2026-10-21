package identity

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const hardwareTestsEnv = "GAF_MACHINEID_HARDWARE_TESTS"

func TestHostname(t *testing.T) {
	t.Parallel()

	hostname, err := Hostname()
	require.NoError(t, err)
	require.NotEmpty(t, hostname)
}

func TestSerialNumber_WrapsQueryError(t *testing.T) {
	cause := errors.New("query failed")
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) { return "", cause }

	_, err := SerialNumber()
	require.ErrorIs(t, err, cause)
}

func TestSerialNumber_PlaceholderSerialIsEmptyWithoutError(t *testing.T) {
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) { return "To Be Filled By O.E.M.", nil }

	serial, err := SerialNumber()
	require.NoError(t, err)
	require.Empty(t, serial)
}

func resetInFlightSerial(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		serialMu.Lock()
		defer serialMu.Unlock()
		inFlightSerial = nil
	})
}

func TestSerialNumber_HungQueryIsNotStartedAgainByLaterCalls(t *testing.T) {
	originalTimeout := serialQueryTimeout
	serialQueryTimeout = 10 * time.Millisecond
	t.Cleanup(func() { serialQueryTimeout = originalTimeout })
	resetInFlightSerial(t)

	release := make(chan struct{})
	var invocations atomic.Int32
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) {
		invocations.Add(1)
		<-release
		return "C02Q7KHTGFWF", nil
	}
	t.Cleanup(func() { close(release) })

	for call := 1; call <= 3; call++ {
		_, err := SerialNumber()
		require.Error(t, err, "call %d", call)
	}
	require.Equal(t, int32(1), invocations.Load())
}

func TestSerialNumber_LateResultOfHungQueryIsReturnedByLaterCall(t *testing.T) {
	originalTimeout := serialQueryTimeout
	serialQueryTimeout = 100 * time.Millisecond
	t.Cleanup(func() { serialQueryTimeout = originalTimeout })
	resetInFlightSerial(t)

	release := make(chan struct{})
	var invocations atomic.Int32
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) {
		invocations.Add(1)
		<-release
		return "C02Q7KHTGFWF", nil
	}

	_, err := SerialNumber()
	require.Error(t, err)

	close(release)

	serial, err := SerialNumber()
	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", serial)
	require.Equal(t, int32(1), invocations.Load())
}

func TestSerialNumber_ReturnsErrorWhenQueryHangs(t *testing.T) {
	originalTimeout := serialQueryTimeout
	serialQueryTimeout = 10 * time.Millisecond
	t.Cleanup(func() { serialQueryTimeout = originalTimeout })
	resetInFlightSerial(t)

	release := make(chan struct{})
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) {
		<-release
		return "C02Q7KHTGFWF", nil
	}
	t.Cleanup(func() { close(release) })

	start := time.Now()
	_, err := SerialNumber()
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
}
