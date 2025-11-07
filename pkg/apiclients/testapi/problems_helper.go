package testapi

import "bytes"

// GetID extracts the ID field from a Problem without full unmarshaling.
// Returns empty string if the Problem variant doesn't have an ID field (e.g., "other" type).
// This uses fast byte scanning instead of json.Unmarshal for better performance.
func (p Problem) GetID() string {
	// Fast path: scan for "id":"value" pattern in JSON bytes
	// This is 5-10x faster than json.Unmarshal for this simple case
	return extractJSONStringField(p.union, "id")
}

// extractJSONStringField efficiently extracts a string field from JSON bytes.
// Returns empty string if field not found or parsing fails.
func extractJSONStringField(data []byte, fieldName string) string {
	searchPattern := []byte(`"` + fieldName + `"`)
	idx := bytes.Index(data, searchPattern)
	if idx == -1 {
		return ""
	}

	pos := skipToValueStart(data, idx+len(searchPattern))
	if pos == -1 {
		return ""
	}

	end := findClosingQuote(data, pos)
	if end == -1 {
		return ""
	}

	return string(data[pos:end])
}

// skipToValueStart skips past colon and whitespace to find the opening quote.
func skipToValueStart(data []byte, pos int) int {
	// Skip whitespace before colon
	pos = skipWhitespace(data, pos)
	if pos >= len(data) || data[pos] != ':' {
		return -1
	}
	pos++ // Skip colon

	// Skip whitespace after colon
	pos = skipWhitespace(data, pos)
	if pos >= len(data) || data[pos] != '"' {
		return -1
	}
	return pos + 1 // Skip opening quote
}

// skipWhitespace skips JSON whitespace characters.
func skipWhitespace(data []byte, pos int) int {
	for pos < len(data) && isWhitespace(data[pos]) {
		pos++
	}
	return pos
}

// isWhitespace checks if a byte is JSON whitespace.
func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// findClosingQuote finds the closing quote, handling escaped quotes.
func findClosingQuote(data []byte, start int) int {
	for i := start; i < len(data); i++ {
		if data[i] == '"' && !isEscapedQuote(data, start, i) {
			return i
		}
	}
	return -1
}

// isEscapedQuote checks if a quote is escaped by counting preceding backslashes.
func isEscapedQuote(data []byte, start, pos int) bool {
	if pos == start || data[pos-1] != '\\' {
		return false
	}
	// Count consecutive backslashes
	backslashes := 0
	for i := pos - 1; i >= start && data[i] == '\\'; i-- {
		backslashes++
	}
	// Odd number means the quote is escaped
	return backslashes%2 == 1
}

// HasID returns true if this Problem variant has an ID field.
// Most Problem types have an ID except for "other".
func (p Problem) HasID() bool {
	return p.GetID() != ""
}
