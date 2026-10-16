package identity

import (
	"errors"
	"testing"
	"time"
)

const hardwareTestsEnv = "GAF_MACHINEID_HARDWARE_TESTS"

func TestHostname(t *testing.T) {
	t.Parallel()

	hostname, err := Hostname()
	if err != nil {
		t.Fatalf("Hostname() error = %v", err)
	}
	if hostname == "" {
		t.Fatal("expected non-empty hostname")
	}
}

func TestSerialNumber_WrapsQueryError(t *testing.T) {
	cause := errors.New("query failed")
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) { return "", cause }

	_, err := SerialNumber()
	if !errors.Is(err, cause) {
		t.Fatalf("SerialNumber() error = %v, want it to wrap %v", err, cause)
	}
}

func TestSerialNumber_PlaceholderSerialIsEmptyWithoutError(t *testing.T) {
	original := readSerial
	t.Cleanup(func() { readSerial = original })
	readSerial = func() (string, error) { return "To Be Filled By O.E.M.", nil }

	serial, err := SerialNumber()
	if err != nil {
		t.Fatalf("SerialNumber() error = %v, want nil", err)
	}
	if serial != "" {
		t.Fatalf("SerialNumber() = %q, want empty for a placeholder serial", serial)
	}
}

func TestSerialNumber_ReturnsErrorWhenQueryHangs(t *testing.T) {
	originalTimeout := serialQueryTimeout
	serialQueryTimeout = 10 * time.Millisecond
	t.Cleanup(func() { serialQueryTimeout = originalTimeout })

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
	if err == nil {
		t.Fatal("SerialNumber() error = nil, want timeout error")
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("SerialNumber() took %v, want it to give up after the query timeout", elapsed)
	}
}
