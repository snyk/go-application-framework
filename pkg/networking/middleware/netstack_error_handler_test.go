package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

// Define a custom type for context keys to avoid collisions
type contextKey string

const testContextKey contextKey = "test-key"

func Test_NetworkStackErrorHandlerMiddleware(t *testing.T) {
	t.Run("NewNetworkStackErrorHandlerMiddleware", func(t *testing.T) {
		next := http.DefaultTransport
		errHandler := func(err error, ctx context.Context) error {
			return err
		}

		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		assert.NotNil(t, middlewareInstance)
		// We can't test private fields directly, but we can test that the middleware was created
	})

	t.Run("RoundTrip with nil error", func(t *testing.T) {
		// Create a mock that returns success (no error)
		next := &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			},
		}

		errHandler := func(err error, ctx context.Context) error {
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		resp, err := middlewareInstance.RoundTrip(req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("handleError with regular Go error - converts to snyk_errors.Error", func(t *testing.T) {
		regularError := errors.New("regular network error")

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(regularError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedError)

		// Verify that the regular error was converted to snyk_errors.Error
		var snykError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &snykError))
		assert.Equal(t, "Network Error", snykError.Title)
		assert.Equal(t, "An error occurred while making a network request.", snykError.Description)
		assert.Contains(t, snykError.Detail, "http://example.com/test")
		assert.Contains(t, snykError.Detail, "regular network error")
		assert.Equal(t, 0, snykError.StatusCode)
		assert.Equal(t, "error", snykError.Level)
		assert.Equal(t, "SNYK-CLI-0044", snykError.ErrorCode)
		assert.Equal(t, "ACTIONABLE", snykError.Classification)
		assert.Equal(t, regularError, snykError.Cause)
	})

	t.Run("handleError with existing snyk_errors.Error - passes through unchanged", func(t *testing.T) {
		originalError := snyk.NewBadRequestError("Original error")
		originalError.ErrorCode = "TEST-001"

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(originalError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedError)

		// Verify that the original snyk error was passed through unchanged
		var snykError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &snykError))
		assert.Equal(t, originalError.Title, snykError.Title)
		assert.Equal(t, originalError.ErrorCode, snykError.ErrorCode)
		assert.Equal(t, "TEST-001", snykError.ErrorCode)
	})

	t.Run("handleError with wrapped snyk_errors.Error - passes through unchanged", func(t *testing.T) {
		// Create a wrapped snyk error
		originalError := snyk.NewUnauthorisedError("Wrapped error")
		originalError.ErrorCode = "TEST-002"
		wrappedError := fmt.Errorf("wrapper: %w", originalError)

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(wrappedError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedError)

		// Verify that the wrapped snyk error was passed through unchanged
		var snykError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &snykError))
		assert.Equal(t, originalError.Title, snykError.Title)
		assert.Equal(t, originalError.ErrorCode, snykError.ErrorCode)
		assert.Equal(t, "TEST-002", snykError.ErrorCode)
	})

	t.Run("handleError calls error handler with context", func(t *testing.T) {
		regularError := errors.New("test error")

		var capturedContext context.Context
		errHandler := func(err error, ctx context.Context) error {
			capturedContext = ctx
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		// Create request with context
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)
		ctx := context.WithValue(context.Background(), testContextKey, "test-value")
		req = req.WithContext(ctx)

		result := middlewareInstance.handleError(regularError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedContext)
		assert.Equal(t, "test-value", capturedContext.Value(testContextKey))
	})

	t.Run("handleError allows error handler to modify error", func(t *testing.T) {
		regularError := errors.New("original error")

		modifiedError := errors.New("modified error")
		errHandler := func(err error, ctx context.Context) error {
			return modifiedError
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(regularError, req)

		// Verify that the error was modified by the error handler
		assert.Error(t, result)
		assert.Equal(t, modifiedError, result)
	})

	t.Run("RoundTrip with no error", func(t *testing.T) {
		// Create a mock that returns success
		next := &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			},
		}

		errHandler := func(err error, ctx context.Context) error {
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		// Create request
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		// Execute request
		resp, err := middlewareInstance.RoundTrip(req)

		// Verify success
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("RoundTrip with error - calls handleError", func(t *testing.T) {
		// Create a mock that returns an error
		regularError := errors.New("network error")
		next := &mockRoundTripper{
			err: regularError,
		}

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		// Create request
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		// Execute request
		resp, err := middlewareInstance.RoundTrip(req)

		// Verify error handling
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.NotNil(t, capturedError)

		// Verify that the error was converted to snyk_errors.Error
		var snykError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &snykError))
		assert.Equal(t, "Network Error", snykError.Title)
		assert.Equal(t, "SNYK-CLI-0044", snykError.ErrorCode)
	})
}

// mockRoundTripper is a mock implementation of http.RoundTripper for testing
type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}
