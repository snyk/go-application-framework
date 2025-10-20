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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
)

const (
	// MaxPayloadSize is the maximum size in bytes for a single API request (1MB)
	MaxPayloadSize = 1024 * 1024 // 1MB

	// DefaultMaxBufferSize is the default maximum buffer size in bytes (10MB)
	DefaultMaxBufferSize = 10 * 1024 * 1024 // 10MB
)

// LogEntry represents a single log message with its level and timestamp
type LogEntry struct {
	Level     zerolog.Level `json:"level"`
	Message   string        `json:"message"`
	Timestamp time.Time     `json:"timestamp"`
}

func (l *LogEntry) toJSON() ([]byte, error) {
	return json.Marshal(toLogMessage(l))
}

// Batch represents a collection of log entries that will be sent together
type Batch []LogEntry

// Size returns the approximate serialized JSON size of the batch in bytes
func (b Batch) Size() (int, error) {
	if len(b) == 0 {
		return 2, nil // Empty array: []
	}

	totalSize := 2 // Account for array brackets []
	for i, entry := range b {
		entryBytes, err := entry.toJSON()
		if err != nil {
			return 0, err
		}
		totalSize += len(entryBytes)
		if i < len(b)-1 {
			totalSize++ // Add comma separator
		}
	}
	return totalSize, nil
}

// toLogMessage converts a LogEntry to the API LogMessage format
func toLogMessage(entry *LogEntry) v20241015.LogMessage {
	level := convertLogLevel(entry.Level)
	message := entry.Message
	return v20241015.LogMessage{
		Level:      &level,
		LogMessage: &message,
	}
}

// ToAPIFormat converts the batch to a slice of LogMessage
func (b Batch) ToAPIFormat() []v20241015.LogMessage {
	var logMessages []v20241015.LogMessage
	for _, entry := range b {
		logMessages = append(logMessages, toLogMessage(&entry))
	}
	return logMessages
}

// APILogWriterConfig holds configuration for the API log writer
type APILogWriterConfig struct {
	// MaxBufferSize is the maximum buffer size in bytes (default: 10MB)
	MaxBufferSize int
	// TriggerLevel is the minimum log level that triggers sending the buffer
	TriggerLevel zerolog.Level
	// LdxSyncClient is the LDX Sync API client for sending logs
	LdxSyncClient v20241015.ClientWithResponsesInterface
	// LogSource contains integration information for the log source
	LogSource v20241015.LogSource
	// OnError is called when sending logs fails (optional)
	OnError func(error)
}

// APILogWriter buffers log messages and sends them to an API endpoint
// when a log message with level >= TriggerLevel is received
type APILogWriter struct {
	mu                sync.RWMutex
	config            APILogWriterConfig
	buffer            []LogEntry
	currentBufferSize int // Current buffer size in bytes
	underlyingWriter  zerolog.LevelWriter
}

// NewAPILogWriter creates a new API log writer with the given configuration
func NewAPILogWriter(config APILogWriterConfig, underlyingWriter zerolog.LevelWriter) *APILogWriter {
	if config.MaxBufferSize <= 0 {
		config.MaxBufferSize = DefaultMaxBufferSize
	}
	// If TriggerLevel is not set (default zero value is DebugLevel),
	// set it to ErrorLevel as a reasonable default for API logging
	if config.TriggerLevel == 0 {
		config.TriggerLevel = zerolog.ErrorLevel // default trigger level
	}
	return &APILogWriter{
		config:            config,
		buffer:            make([]LogEntry, 0),
		currentBufferSize: 0,
		underlyingWriter:  underlyingWriter,
	}
}

// WriteLevel implements zerolog.LevelWriter
func (w *APILogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	// First write to underlying writer if present
	var writeErr error
	bytesWritten := len(p)
	if w.underlyingWriter != nil {
		bytesWritten, writeErr = w.underlyingWriter.WriteLevel(level, p)
	}

	// Add to buffer
	w.mu.Lock()
	entry := LogEntry{
		Level:     level,
		Message:   string(p),
		Timestamp: time.Now(),
	}

	// Calculate approximate entry size
	entrySize := len(p) + 50 // Message + overhead for level, timestamp, JSON structure

	// Add entry to buffer
	w.buffer = append(w.buffer, entry)
	w.currentBufferSize += entrySize

	// Trim buffer if it exceeds max size (keep most recent entries)
	for w.currentBufferSize > w.config.MaxBufferSize && len(w.buffer) > 0 {
		// Remove oldest entry
		removedEntry := w.buffer[0]
		removedSize := len(removedEntry.Message) + 50
		w.buffer = w.buffer[1:]
		w.currentBufferSize -= removedSize
	}

	// Check if we should trigger a send
	shouldSend := level >= w.config.TriggerLevel
	var bufferCopy []LogEntry
	if shouldSend {
		// Create a copy of the buffer to send
		bufferCopy = make([]LogEntry, len(w.buffer))
		copy(bufferCopy, w.buffer)
		// Clear the buffer after copying
		w.buffer = make([]LogEntry, 0)
		w.currentBufferSize = 0
	}
	w.mu.Unlock()

	// Send logs asynchronously if triggered
	if shouldSend && len(bufferCopy) > 0 {
		go w.sendLogs(bufferCopy)
	}

	return bytesWritten, writeErr
}

// Write implements io.Writer interface
func (w *APILogWriter) Write(p []byte) (int, error) {
	// Default to Info level when no level is specified
	return w.WriteLevel(zerolog.InfoLevel, p)
}

// sendLogs sends the buffered logs to the API endpoint in batches to ensure
// each payload is under MaxPayloadSize (1MB)
func (w *APILogWriter) sendLogs(entries []LogEntry) {
	if w.config.LdxSyncClient == nil {
		return
	}

	// Split entries into batches based on payload size
	batches := w.batchEntriesBySize(entries)

	// Send each batch
	for _, batch := range batches {
		w.sendBatch(batch)
	}
}

// batchEntriesBySize splits log entries into batches where each batch's
// serialized JSON payload is less than MaxPayloadSize
func (w *APILogWriter) batchEntriesBySize(entries []LogEntry) []Batch {
	if len(entries) == 0 {
		return nil
	}

	var batches []Batch
	var currentBatch Batch
	var currentSize int

	for _, entry := range entries {
		// Create a temporary batch with just this entry to get its size
		entryBytes, err := entry.toJSON()
		if err != nil {
			// If we can't marshal, skip this entry
			continue
		}
		entrySize := len(entryBytes) + 1 // +1 for comma in JSON array

		// If this single entry exceeds max size, skip it (log error)
		if entrySize > MaxPayloadSize {
			w.handleError(fmt.Errorf("single log entry exceeds maximum payload size: %d bytes", entrySize))
			continue
		}

		// If adding this entry would exceed max size, start a new batch
		// Account for JSON array overhead: [], commas between entries
		estimatedBatchSize := currentSize + entrySize + 2 // +2 for array brackets
		if len(currentBatch) > 0 && estimatedBatchSize > MaxPayloadSize {
			batches = append(batches, currentBatch)
			currentBatch = Batch{entry}
			currentSize = entrySize
		} else {
			currentBatch = append(currentBatch, entry)
			currentSize += entrySize
		}
	}

	// Add the last batch if it has entries
	if len(currentBatch) > 0 {
		batches = append(batches, currentBatch)
	}

	return batches
}

// sendBatch sends a single batch of log entries to the API
func (w *APILogWriter) sendBatch(batch Batch) {
	// Convert batch to API format
	logMessages := batch.ToAPIFormat()

	// Create request body with log messages and source
	requestBody := v20241015.CreateLogMessageJSONRequestBody{
		LogMessages: logMessages,
		Source:      w.config.LogSource,
	}

	// Send to API with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	version := "2024-10-15"
	params := &v20241015.CreateLogMessageParams{
		Version: version,
	}

	resp, err := w.config.LdxSyncClient.CreateLogMessageWithResponse(ctx, params, requestBody)
	if err != nil {
		w.handleError(fmt.Errorf("failed to send logs: %w", err))
		return
	}

	// Check response status
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		w.handleError(fmt.Errorf("API returned non-success status: %d", resp.StatusCode()))
		return
	}
}

// convertLogLevel converts zerolog.Level to the API log level
func convertLogLevel(level zerolog.Level) v20241015.LogMessageLevel {
	switch level {
	case zerolog.DebugLevel, zerolog.TraceLevel:
		return v20241015.LogMessageLevelDebug
	case zerolog.InfoLevel:
		return v20241015.LogMessageLevelInfo
	case zerolog.WarnLevel:
		return v20241015.LogMessageLevelWarn
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		return v20241015.LogMessageLevelError
	default:
		return v20241015.LogMessageLevelInfo
	}
}

// handleError calls the OnError callback if configured
func (w *APILogWriter) handleError(err error) {
	if w.config.OnError != nil {
		w.config.OnError(err)
	}
}

// Flush sends any remaining buffered logs to the API endpoint
func (w *APILogWriter) Flush() error {
	w.mu.Lock()
	bufferCopy := make([]LogEntry, len(w.buffer))
	copy(bufferCopy, w.buffer)
	w.buffer = make([]LogEntry, 0)
	w.currentBufferSize = 0
	w.mu.Unlock()

	if len(bufferCopy) > 0 {
		w.sendLogs(bufferCopy)
	}

	return nil
}

// GetBufferSize returns the current buffer size in bytes
func (w *APILogWriter) GetBufferSize() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.currentBufferSize
}

// GetBufferEntryCount returns the current number of entries in the buffer
func (w *APILogWriter) GetBufferEntryCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.buffer)
}

// Clear removes all entries from the buffer
func (w *APILogWriter) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buffer = make([]LogEntry, 0)
	w.currentBufferSize = 0
}
