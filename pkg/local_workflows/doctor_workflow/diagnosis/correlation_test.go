package diagnosis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prefixed builds a body line as it looks after CLI-prefix stripping.
func prefixed(n int, msg string) ParsedLine {
	return ParsedLine{Number: n, Message: msg, HasCLIPrefix: true}
}

// continuation builds a body line that carries only the CI runner timestamp
// (no CLI prefix) - e.g. a multi-line HTML error page.
func continuation(n int, msg string) ParsedLine {
	return ParsedLine{Number: n, Message: msg, HasCLIPrefix: false}
}

func onlyFinding(t *testing.T, findings []Finding) Finding {
	t.Helper()
	require.Len(t, findings, 1)
	return findings[0]
}

func TestCorrelation_joinsBySnykRequestID(t *testing.T) {
	// Differing handles (request 0x500, response 0x640); joined via Snyk-Request-Id.
	body := []ParsedLine{
		prefixed(446, "> request [0x500]: GET https://api.snyk.io/v1/cli-config/feature-flags/scanUsrLibJars?org=myorg"),
		prefixed(447, "> request [0x500]: header: map[Snyk-Request-Id:[e2c8b236-5252-4dbe-a276-513cdb81fad9]]"),
		prefixed(448, "< response [0x640]: 403 Forbidden"),
		prefixed(449, "< response [0x640]: header: map[Snyk-Request-Id:[e2c8b236-5252-4dbe-a276-513cdb81fad9]]"),
		prefixed(450, `< response [0x640]: body: {"ok":false,"userMessage":"Org myorg doesn't have 'scan-usr-lib-jars' feature enabled"}`),
	}

	f := onlyFinding(t, (&CorrelationCheck{}).Analyze(body))

	assert.Equal(t, ProducerLogAnalysis, f.Producer)
	assert.Equal(t, KindCorrelation, f.Kind)
	assert.Equal(t, SeverityError, f.Severity)
	assert.Equal(t, "snyk-request-id", f.Fields[FieldCorrelatedBy])
	assert.Equal(t, "GET", f.Fields[FieldMethod])
	assert.Equal(t, "403", f.Fields[FieldStatus])
	assert.Equal(t, "e2c8b236-5252-4dbe-a276-513cdb81fad9", f.Fields[FieldSnykRequestID])
	assert.Contains(t, f.Fields[FieldURL], "scanUsrLibJars")
	// Summary is the title; the decoded reason is the message.
	assert.Contains(t, f.Title, "403 Forbidden: GET")
	assert.Contains(t, f.Message, "doesn't have 'scan-usr-lib-jars' feature enabled")
	// Lines span the request line + response status + body rows (header rows are
	// used only to extract the Snyk-Request-Id, not tracked as finding lines).
	assert.Equal(t, []int{446, 448, 450}, f.Lines)
}

func TestCorrelation_akamaiEdgeBlockNoRequestID(t *testing.T) {
	// The Akamai response has no Snyk-Request-Id and a multi-line HTML body with
	// entity escapes; attribution falls back to matching the URL from the body.
	body := []ParsedLine{
		prefixed(520, "> request [0xa8c0]: PUT https://api.snyk.io:443/v1/monitor-dependencies?org=myorg"),
		prefixed(521, "> request [0xa8c0]: header: map[Snyk-Request-Id:[77e4a007-bd8d-42d2-9646-d7bd5113a20a]]"),
		prefixed(522, "< response [0xaa00]: 403 Forbidden"),
		prefixed(523, "< response [0xaa00]: header: map[Server:[AkamaiGHost]]"),
		prefixed(524, "< response [0xaa00]: body: <HTML><HEAD>"),
		continuation(525, "2026-06-26T13:58:32.0Z <TITLE>Access Denied</TITLE>"),
		continuation(529, `2026-06-26T13:58:32.0Z You don't have permission to access "http&#58;&#47;&#47;api&#46;snyk&#46;io&#47;v1&#47;monitor&#45;dependencies&#63;" on this server.<P>`),
		continuation(530, "2026-06-26T13:58:32.0Z Reference&#32;&#35;18&#46;73643017&#46;1782482311&#46;65647328"),
		continuation(533, "2026-06-26T13:58:32.0Z </HTML>"),
	}

	f := onlyFinding(t, (&CorrelationCheck{}).Analyze(body))

	assert.Equal(t, KindCorrelation, f.Kind)
	// Linked to the PUT request via the URL decoded from the body.
	assert.Equal(t, "url", f.Fields[FieldCorrelatedBy])
	assert.Equal(t, "PUT", f.Fields[FieldMethod])
	assert.Equal(t, "akamai", f.Fields[FieldEdge])
	assert.Equal(t, "18.73643017.1782482311.65647328", f.Fields[FieldEdgeReference])
	// The decoded reason is the message - readable, no HTML entities or tags leak.
	assert.Contains(t, f.Message, "monitor-dependencies")
	assert.NotContains(t, f.Message, "&#")
	assert.NotContains(t, f.Message, "<")
}

func TestCorrelation_adjacencyWhenUnambiguous(t *testing.T) {
	// No Snyk-Request-Id and no body URL: attributed to the nearest preceding
	// request only because nothing is interleaved between them.
	body := []ParsedLine{
		prefixed(1, "> request [0xaaa]: GET https://api.snyk.io/rest/self"),
		prefixed(2, "> request [0xaaa]: header: map[Snyk-Request-Id:[req-1]]"),
		prefixed(3, "< response [0xbbb]: 500 Internal Server Error"),
	}

	f := onlyFinding(t, (&CorrelationCheck{}).Analyze(body))

	assert.Equal(t, "adjacency", f.Fields[FieldCorrelatedBy])
	assert.Equal(t, "GET", f.Fields[FieldMethod])
	assert.Equal(t, "500", f.Fields[FieldStatus])
}

func TestCorrelation_skipsAdjacencyWhenInterleaved(t *testing.T) {
	// Another response block sits between the request and the failing response,
	// so adjacency must not guess - the finding is emitted response-only.
	body := []ParsedLine{
		prefixed(1, "> request [0xaaa]: GET https://api.snyk.io/rest/self"),
		prefixed(2, "< response [0xddd]: 200 OK"),
		prefixed(3, "< response [0xbbb]: 500 Internal Server Error"),
	}

	f := onlyFinding(t, (&CorrelationCheck{}).Analyze(body))

	assert.Equal(t, "none", f.Fields[FieldCorrelatedBy])
	assert.NotContains(t, f.Fields, FieldMethod)
	assert.Equal(t, "500 Internal Server Error", f.Message)
}

func TestCorrelation_ignoresSuccessResponses(t *testing.T) {
	body := []ParsedLine{
		prefixed(1, "> request [0xaaa]: GET https://api.snyk.io/rest/self"),
		prefixed(2, "< response [0xbbb]: 200 OK"),
		prefixed(3, "< response [0xccc]: 304 Not Modified"),
	}

	assert.Empty(t, (&CorrelationCheck{}).Analyze(body))
}
