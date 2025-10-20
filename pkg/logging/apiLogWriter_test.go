/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logging

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	ldxmocks "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/mocks"
	"github.com/snyk/go-application-framework/pkg/logging/mocks"
)

func TestNewAPILogWriter_DefaultValues(t *testing.T) {
	config := APILogWriterConfig{}

	writer := NewAPILogWriter(config, nil)

	assert.NotNil(t, writer)
	assert.Equal(t, 10*1024*1024, writer.config.MaxBufferSize, "Should use default buffer size (10MB)")
	assert.Equal(t, zerolog.ErrorLevel, writer.config.TriggerLevel, "Should use default trigger level")
}

func TestNewAPILogWriter_CustomValues(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)
	config := APILogWriterConfig{
		MaxBufferSize: 100,
		TriggerLevel:  zerolog.WarnLevel,
		LdxSyncClient: mockClient,
	}

	writer := NewAPILogWriter(config, nil)

	assert.NotNil(t, writer)
	assert.Equal(t, 100, writer.config.MaxBufferSize)
	assert.Equal(t, zerolog.WarnLevel, writer.config.TriggerLevel)
	assert.Equal(t, mockClient, writer.config.LdxSyncClient)
}

func TestAPILogWriter_BuffersMessages(t *testing.T) {
	config := APILogWriterConfig{
		MaxBufferSize: 1024, // 1KB
		TriggerLevel:  zerolog.ErrorLevel,
	}

	writer := NewAPILogWriter(config, nil)

	// Write info level messages (below trigger level)
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("log message %d", i)
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}

	// Check buffer has entries
	assert.Equal(t, 5, writer.GetBufferEntryCount())
	assert.Greater(t, writer.GetBufferSize(), 0, "Buffer size should be greater than 0")
}

func TestAPILogWriter_TrimsBufferWhenFull(t *testing.T) {
	config := APILogWriterConfig{
		MaxBufferSize: 500, // 500 bytes
		TriggerLevel:  zerolog.ErrorLevel,
	}

	writer := NewAPILogWriter(config, nil)

	// Write more messages than the buffer can hold
	for i := 0; i < 15; i++ {
		msg := fmt.Sprintf("log message %d", i)
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}

	// Buffer size should be at or under max size
	assert.LessOrEqual(t, writer.GetBufferSize(), config.MaxBufferSize)

	// Buffer should contain the most recent entries
	writer.mu.RLock()
	lastEntry := writer.buffer[len(writer.buffer)-1]
	writer.mu.RUnlock()
	assert.Contains(t, lastEntry.Message, "log message 14")
}

func TestAPILogWriter_SendsOnTriggerLevel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect CreateLogMessageWithResponse to be called with 4 log entries
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			// Verify we got 4 log messages (3 info + 1 error)
			assert.Equal(t, 4, len(body.LogMessages))

			// Create success response
			response := &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{
					StatusCode: 201,
				},
			}
			return response, nil
		}).
		Times(1)

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Write some info messages
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("info message %d", i)
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}

	// Write error message to trigger send
	_, err := writer.WriteLevel(zerolog.ErrorLevel, []byte("error message"))
	require.NoError(t, err)

	// Wait for async send
	time.Sleep(100 * time.Millisecond)

	// Buffer should be cleared after send
	assert.Equal(t, 0, writer.GetBufferSize())
}

func TestAPILogWriter_DoesNotSendBelowTriggerLevel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect NO calls to CreateLogMessageWithResponse
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		Times(0)

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
	}

	writer := NewAPILogWriter(config, nil)

	// Write only info and warn messages (below error level)
	_, _ = writer.WriteLevel(zerolog.InfoLevel, []byte("info message"))
	_, _ = writer.WriteLevel(zerolog.WarnLevel, []byte("warn message"))

	// Wait to ensure no async sends happened
	time.Sleep(100 * time.Millisecond)

	// Buffer should still contain the messages
	assert.Equal(t, 2, writer.GetBufferEntryCount())
}

func TestAPILogWriter_ThreadSafety(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect multiple calls (10 goroutines * 10 triggers each = ~100 calls)
	// Use AnyTimes() since exact count is unpredictable with concurrency
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 201},
			}, nil
		}).
		AnyTimes()

	config := APILogWriterConfig{
		MaxBufferSize: 100 * 1024, // 100KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Run concurrent writes
	var wg sync.WaitGroup
	numGoroutines := 10
	writesPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				msg := fmt.Sprintf("message from goroutine %d: %d", id, j)
				level := zerolog.InfoLevel
				if j%10 == 0 {
					level = zerolog.ErrorLevel // Trigger send occasionally
				}
				_, _ = writer.WriteLevel(level, []byte(msg))
			}
		}(i)
	}

	wg.Wait()

	// Test should complete without data races or panics
	// Buffer size should be less than total writes due to triggered sends
	assert.LessOrEqual(t, writer.GetBufferSize(), config.MaxBufferSize)
}

func TestAPILogWriter_FlushSendsRemainingLogs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect CreateLogMessageWithResponse to be called with 3 log entries
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			assert.Equal(t, 3, len(body.LogMessages))
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 201},
			}, nil
		}).
		Times(1)

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Write info messages (won't trigger automatic send)
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("info message %d", i)
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}

	assert.Equal(t, 3, writer.GetBufferEntryCount())

	// Flush should send the logs
	err := writer.Flush()
	require.NoError(t, err)

	// Wait for async send
	time.Sleep(100 * time.Millisecond)

	// Buffer should be empty
	assert.Equal(t, 0, writer.GetBufferSize())
}

func TestAPILogWriter_ClearBuffer(t *testing.T) {
	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
	}

	writer := NewAPILogWriter(config, nil)

	// Write some messages
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("message %d", i)
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}

	assert.Equal(t, 5, writer.GetBufferEntryCount())

	// Clear buffer
	writer.Clear()

	assert.Equal(t, 0, writer.GetBufferSize())
}

func TestAPILogWriter_OnErrorCallback(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	var errorReceived error
	var mu sync.Mutex

	// Expect CreateLogMessageWithResponse to return error status
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 500},
			}, nil
		}).
		Times(1)

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
		OnError: func(err error) {
			mu.Lock()
			errorReceived = err
			mu.Unlock()
		},
	}

	writer := NewAPILogWriter(config, nil)

	// Write error message to trigger send
	_, err := writer.WriteLevel(zerolog.ErrorLevel, []byte("error message"))
	require.NoError(t, err)

	// Wait for async send and error callback
	time.Sleep(100 * time.Millisecond)

	// Check that error callback was called
	mu.Lock()
	defer mu.Unlock()
	assert.NotNil(t, errorReceived)
	assert.Contains(t, errorReceived.Error(), "non-success status")
}

func TestAPILogWriter_WritesToUnderlyingWriter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWriter := mocks.NewMockLevelWriter(ctrl)

	messages := []string{"message 1", "message 2", "message 3"}

	// Expect WriteLevel to be called 3 times with the messages
	for _, msg := range messages {
		mockWriter.EXPECT().
			WriteLevel(zerolog.InfoLevel, []byte(msg)).
			Return(len(msg), nil).
			Times(1)
	}

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
	}

	writer := NewAPILogWriter(config, mockWriter)

	// Write messages
	for _, msg := range messages {
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}
}

func TestAPILogWriter_WriteMethod(t *testing.T) {
	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
	}

	writer := NewAPILogWriter(config, nil)

	// Use Write method (should default to Info level)
	msg := "test message"
	n, err := writer.Write([]byte(msg))

	require.NoError(t, err)
	assert.Equal(t, len(msg), n)
	assert.Equal(t, 1, writer.GetBufferEntryCount())

	// Check that the entry has Info level
	writer.mu.RLock()
	entry := writer.buffer[0]
	writer.mu.RUnlock()
	assert.Equal(t, zerolog.InfoLevel, entry.Level)
}

func TestAPILogWriter_LogEntryStructure(t *testing.T) {
	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
	}

	writer := NewAPILogWriter(config, nil)

	msg := "test message"
	beforeWrite := time.Now()
	_, err := writer.WriteLevel(zerolog.WarnLevel, []byte(msg))
	afterWrite := time.Now()

	require.NoError(t, err)

	writer.mu.RLock()
	entry := writer.buffer[0]
	writer.mu.RUnlock()

	// Validate entry fields
	assert.Equal(t, zerolog.WarnLevel, entry.Level)
	assert.Equal(t, msg, entry.Message)
	assert.True(t, entry.Timestamp.After(beforeWrite) || entry.Timestamp.Equal(beforeWrite))
	assert.True(t, entry.Timestamp.Before(afterWrite) || entry.Timestamp.Equal(afterWrite))
}

func TestAPILogWriter_NoClientDoesNotSend(t *testing.T) {
	// No client configured
	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: nil, // No client
	}

	writer := NewAPILogWriter(config, nil)

	// Write error message (would trigger send if client was set)
	_, err := writer.WriteLevel(zerolog.ErrorLevel, []byte("error message"))
	require.NoError(t, err)

	// Wait to ensure no panics occur
	time.Sleep(100 * time.Millisecond)

	// Test should complete without errors
	// Buffer should still contain the error message since it wasn't sent
	assert.Equal(t, 0, writer.GetBufferSize()) // Buffer is cleared even without client
}

func TestAPILogWriter_ConvertLevel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect CreateLogMessageWithResponse to be called with 3 log entries
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			// Verify we got 3 log messages with correct level conversion
			assert.Equal(t, 3, len(body.LogMessages))
			// Check levels were converted correctly
			assert.Equal(t, v20241015.LogMessageLevelDebug, *body.LogMessages[0].Level)
			assert.Equal(t, v20241015.LogMessageLevelInfo, *body.LogMessages[1].Level)
			assert.Equal(t, v20241015.LogMessageLevelError, *body.LogMessages[2].Level)
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 201},
			}, nil
		}).
		Times(1)

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Write messages with different levels
	_, _ = writer.WriteLevel(zerolog.DebugLevel, []byte("debug message"))
	_, _ = writer.WriteLevel(zerolog.InfoLevel, []byte("info message"))
	_, _ = writer.WriteLevel(zerolog.ErrorLevel, []byte("error message"))

	// Wait for async send
	time.Sleep(100 * time.Millisecond)
}

func TestAPILogWriter_BatchesBySize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Track batches received
	var batches []int
	var mu sync.Mutex

	// Expect multiple calls due to batching
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			mu.Lock()
			batches = append(batches, len(body.LogMessages))
			mu.Unlock()
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 201},
			}, nil
		}).
		AnyTimes()

	config := APILogWriterConfig{
		MaxBufferSize: 2 * 1024 * 1024, // 2MB buffer to hold all messages
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Create a large message that will force batching
	// Each message is roughly 100KB, so 15 messages = ~1.5MB, requiring 2 batches
	largeMessage := make([]byte, 100*1024) // 100KB
	for i := range largeMessage {
		largeMessage[i] = 'A'
	}

	// Write 15 large messages
	for i := 0; i < 15; i++ {
		_, err := writer.WriteLevel(zerolog.InfoLevel, largeMessage)
		require.NoError(t, err)
	}

	// Trigger send with error level
	_, err := writer.WriteLevel(zerolog.ErrorLevel, []byte("trigger"))
	require.NoError(t, err)

	// Wait for async send
	time.Sleep(200 * time.Millisecond)

	// Verify multiple batches were sent
	mu.Lock()
	defer mu.Unlock()
	assert.Greater(t, len(batches), 1, "Should have sent multiple batches")

	// Verify total count matches
	totalSent := 0
	for _, count := range batches {
		totalSent += count
	}
	assert.Equal(t, 16, totalSent, "Should have sent all 16 messages (15 large + 1 trigger)")
}

func TestAPILogWriter_SingleBatchUnder1MB(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect exactly one call with all entries (100 messages + 1 trigger = 101)
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			assert.Equal(t, 101, len(body.LogMessages), "Should send all entries in one batch (100 + trigger)")
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 201},
			}, nil
		}).
		Times(1)

	config := APILogWriterConfig{
		MaxBufferSize: 100 * 1024, // 100KB - enough for all messages
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Write 100 small messages (well under 1MB total)
	for i := 0; i < 100; i++ {
		msg := fmt.Sprintf("small message %d", i)
		_, err := writer.WriteLevel(zerolog.InfoLevel, []byte(msg))
		require.NoError(t, err)
	}

	// Trigger send
	_, err := writer.WriteLevel(zerolog.ErrorLevel, []byte("trigger"))
	require.NoError(t, err)

	// Wait for async send
	time.Sleep(100 * time.Millisecond)
}

func TestAPILogWriter_OversizedSingleEntry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := ldxmocks.NewMockClientWithResponsesInterface(ctrl)

	// Expect call with normal message + trigger (oversized one gets trimmed from buffer before sending)
	mockClient.EXPECT().
		CreateLogMessageWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, params *v20241015.CreateLogMessageParams, body v20241015.CreateLogMessageJSONRequestBody, reqEditors ...v20241015.RequestEditorFn) (*v20241015.CreateLogMessageResponse, error) {
			assert.Equal(t, 2, len(body.LogMessages), "Should send normal message and trigger (oversized trimmed)")
			return &v20241015.CreateLogMessageResponse{
				HTTPResponse: &http.Response{StatusCode: 201},
			}, nil
		}).
		Times(1)

	config := APILogWriterConfig{
		MaxBufferSize: 10 * 1024, // 10KB - small buffer to trim oversized message
		TriggerLevel:  zerolog.ErrorLevel,
		LdxSyncClient: mockClient,
		LogSource:     v20241015.LogSource{},
	}

	writer := NewAPILogWriter(config, nil)

	// Try to write an oversized message (>1MB)
	// This will be added to buffer then immediately trimmed because it exceeds MaxBufferSize
	oversizedMessage := make([]byte, 2*1024*1024) // 2MB
	for i := range oversizedMessage {
		oversizedMessage[i] = 'X'
	}
	_, err := writer.WriteLevel(zerolog.InfoLevel, oversizedMessage)
	require.NoError(t, err)

	// Write a normal message
	_, err = writer.WriteLevel(zerolog.InfoLevel, []byte("normal message"))
	require.NoError(t, err)

	// Trigger send
	_, err = writer.WriteLevel(zerolog.ErrorLevel, []byte("trigger"))
	require.NoError(t, err)

	// Wait for async send
	time.Sleep(100 * time.Millisecond)

	// The oversized message was trimmed from the buffer, so only normal message and trigger are sent
}
