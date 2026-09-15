package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// elapsedForRetries runs a middleware that always needs one retry and reports how
// long the backoff between attempts took.
func elapsedForRetries(t *testing.T, config configuration.Configuration, opts ...RetryMiddlewareOption) (time.Duration, int) {
	t.Helper()

	logger := zerolog.Nop()
	roundTripper := &failRoundtripper{
		NumberOfAttemptsUntilSuccess: 2,
		ExpectedBody:                 []byte("body"),
		t:                            t,
	}

	sut := NewRetryMiddleware(config, &logger, roundTripper, opts...)

	start := time.Now()
	response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader([]byte("body"))))
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, response)

	return elapsed, roundTripper.actualCount
}

func TestWithRetryInterval_ShortensBackoff(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(ConfigurationKeyRequestAttempts, 2)
	config.Set(ConfigurationKeyRetryAfter, 30)

	elapsed, attempts := elapsedForRetries(t, config, WithRetryInterval(50*time.Millisecond))

	assert.Equal(t, 2, attempts)
	assert.Less(t, elapsed, 5*time.Second, "the option must override the configured 30s backoff")
}

func TestWithRetryInterval_AbsentOptionKeepsConfiguredBackoff(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(ConfigurationKeyRequestAttempts, 2)
	config.Set(ConfigurationKeyRetryAfter, 1)

	// Backoff is jittered around the configured 1s, so assert a floor well below it
	// that a 50ms override could not reach.
	elapsed, attempts := elapsedForRetries(t, config)

	assert.Equal(t, 2, attempts)
	assert.Greater(t, elapsed, 300*time.Millisecond, "without the option the configured backoff still applies")
}

func TestWithRetryInterval_DoesNotAffectOtherInstances(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(ConfigurationKeyRequestAttempts, 2)
	config.Set(ConfigurationKeyRetryAfter, 1)

	overridden, _ := elapsedForRetries(t, config, WithRetryInterval(10*time.Millisecond))
	shared, _ := elapsedForRetries(t, config)

	assert.Less(t, overridden, shared, "the override is per instance and must not leak into the shared configuration")
	assert.Equal(t, 1, config.GetInt(ConfigurationKeyRetryAfter), "the configuration itself is untouched")
}
