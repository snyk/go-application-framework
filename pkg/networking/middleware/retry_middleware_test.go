package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type failRoundtripper struct {
	actualCount                  uint
	NumberOfAttemptsUntilSuccess uint
	ExpectedBody                 []byte
	t                            *testing.T
}

func (f *failRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.actualCount++
	f.t.Helper()
	f.t.Logf("%s: roundtrip", time.Now())

	bodyBytes, err := io.ReadAll(req.Body)
	assert.NoError(f.t, err)
	assert.Equal(f.t, f.ExpectedBody, bodyBytes)

	if f.actualCount < f.NumberOfAttemptsUntilSuccess {
		return &http.Response{StatusCode: http.StatusInternalServerError}, nil
	}

	return &http.Response{StatusCode: http.StatusOK}, nil
}

func TestNewRetryMiddleware(t *testing.T) {
	expectedBody := []byte("hello")

	t.Run("Happy path, no retry required", func(t *testing.T) {
		var expectedAttempts uint = 1
		failure := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: expectedAttempts,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()

		sut := NewRetryMiddleware(failure, config)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failure.actualCount)
	})

	t.Run("Happy path, retry resolves successfully", func(t *testing.T) {
		var expectedAttempts uint = 3
		failure := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: expectedAttempts,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()

		sut := NewRetryMiddleware(failure, config)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failure.actualCount)
	})

	t.Run("Unhappy path, retries didn't resolve the issue", func(t *testing.T) {
		var expectedAttempts uint = 3
		failure := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()

		sut := NewRetryMiddleware(failure, config)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, expectedAttempts, failure.actualCount)
	})

}
