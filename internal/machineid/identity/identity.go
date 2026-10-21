// Package identity provides hostname and hardware serial lookups for machine identification.
package identity

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var serialQueryTimeout = 5 * time.Second

var readSerial = readSerialPlatform

type serialQuery struct {
	done   chan struct{}
	serial string
	err    error
}

var (
	serialMu       sync.Mutex
	inFlightSerial *serialQuery
)

// Hostname returns the system hostname.
func Hostname() (string, error) {
	return os.Hostname()
}

// SerialNumber returns the hardware serial number.
// An error means the query failed or timed out. An empty string with a nil error
// means no usable serial is available. On timeout the query is not canceled: the Windows
// WMI query cannot be canceled and keeps running in the background, and later calls wait on it.
func SerialNumber() (string, error) {
	q := joinOrStartSerialQuery()

	select {
	case <-q.done:
		releaseSerialQuery(q)
		if q.err != nil {
			return "", fmt.Errorf("read serial number: %w", q.err)
		}
		return NormalizeSerial(q.serial), nil
	case <-time.After(serialQueryTimeout):
		return "", fmt.Errorf("read serial number: no response after %v", serialQueryTimeout)
	}
}

// joinOrStartSerialQuery shares one query across calls. The WMI query on Windows holds a
// process-wide lock until it returns, so a second concurrent query would only block behind the first.
func joinOrStartSerialQuery() *serialQuery {
	serialMu.Lock()
	defer serialMu.Unlock()

	if inFlightSerial != nil {
		return inFlightSerial
	}
	q := &serialQuery{done: make(chan struct{})}
	query := readSerial
	go func() {
		q.serial, q.err = query()
		close(q.done)
	}()
	inFlightSerial = q
	return q
}

// releaseSerialQuery clears the shared query once a caller has consumed its result. A query
// that timed out is left in place so that a later call receives its result when it completes.
func releaseSerialQuery(q *serialQuery) {
	serialMu.Lock()
	defer serialMu.Unlock()

	if inFlightSerial == q {
		inFlightSerial = nil
	}
}
