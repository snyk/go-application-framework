package logscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scanFixture(t *testing.T, name string) ScanResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return Scan(string(raw))
}

func eventTexts(events []NotableEvent) string {
	var sb strings.Builder
	for _, e := range events {
		sb.WriteString(e.Text)
		sb.WriteString("\n")
	}
	return sb.String()
}

func Test_Scan_emptyConfigLog(t *testing.T) {
	result := scanFixture(t, "empty-config.log")

	assert.Contains(t, result.Header, "Version:")
	assert.Contains(t, result.Header, "API:")
	assert.Contains(t, result.Header, "Checks:")

	assert.Contains(t, result.Footer, "Exit Code:")
	assert.Contains(t, result.Footer, "Authentication error (SNYK-0005)")

	require.NotEmpty(t, result.NotableEvents)
	texts := eventTexts(result.NotableEvents)
	assert.Contains(t, texts, "401 Unauthorized")
	assert.Contains(t, texts, "< error:")

	hasHTTPError := false
	for _, e := range result.NotableEvents {
		if e.Kind == EventHTTPError {
			hasHTTPError = true
		}
		assert.Positive(t, e.Line)
		// header/footer lines must not be double-reported as events
		assert.NotContains(t, e.Text, "Platform:")
	}
	assert.True(t, hasHTTPError)
}

func Test_Scan_wrongEnvironmentLog(t *testing.T) {
	result := scanFixture(t, "wrong-environment.log")

	assert.Contains(t, result.Header, "Version:")
	// the redacted token must survive into the lifted header: it is the
	// evidence that auth material was present despite the 401s
	assert.Contains(t, result.Header, "76f295ce")
	assert.Contains(t, result.Footer, "Exit Code:")

	texts := eventTexts(result.NotableEvents)
	assert.Contains(t, texts, "401 Unauthorized")
}

func Test_Scan_noHeaderFooter(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 500 Internal Server Error",
		"2026-06-10T13:10:38Z main - < error: something broke",
	}, "\n")

	result := Scan(log)

	assert.Empty(t, result.Header)
	assert.Empty(t, result.Footer)
	require.Len(t, result.NotableEvents, 2)
	assert.Equal(t, EventHTTPError, result.NotableEvents[0].Kind)
	assert.Equal(t, 2, result.NotableEvents[0].Line)
	assert.Equal(t, EventError, result.NotableEvents[1].Kind)
}

func Test_Scan_successfulResponsesNotNotable(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 200 OK",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 304 Not Modified",
		"2026-06-10T13:10:38Z main - ⚠️ WARNING: Potentially Sensitive Information ⚠️",
	}, "\n")

	assert.Empty(t, Scan(log).NotableEvents)
}

func Test_Scan_eventCap(t *testing.T) {
	line := "2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 401 Unauthorized\n"
	result := Scan(strings.Repeat(line, maxEvents+50))
	assert.Len(t, result.NotableEvents, maxEvents)
}
