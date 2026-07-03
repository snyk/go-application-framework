package diagnosis

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CorrelationCheck turns HTTP request/response lines into rich, correlated
// findings that answer "why did this fail, and where did it come from".
//
// The response side is grouped reliably by its own hex handle (status + header +
// body share it). The hard part is attributing the response to the originating
// request, because the request handle differs and the join key (Snyk-Request-Id)
// is not always present (e.g. an edge/Akamai block never reaches Snyk). So
// request attribution is best-effort - Snyk-Request-Id, then URL-from-body, then
// guarded positional adjacency - and is recorded in Fields[correlatedBy] so
// confidence is explicit. The response detail (status + decoded reason) is always
// emitted regardless.
type CorrelationCheck struct{}

func (c *CorrelationCheck) Name() string { return "http-correlation" }

var (
	reqLineRe    = regexp.MustCompile(`^> request \[(0x[0-9a-fA-F]+)\]:\s*([A-Z]+)\s+(\S+)`)
	respStatusRe = regexp.MustCompile(`^< response \[(0x[0-9a-fA-F]+)\]:\s*(\d{3})\b\s*(.*)`)
	respBodyRe   = regexp.MustCompile(`^< response \[(0x[0-9a-fA-F]+)\]: body: (.*)`)
	headerRe     = regexp.MustCompile(`^[<>] (?:request|response) \[(0x[0-9a-fA-F]+)\]: header:`)
	snykIDRe     = regexp.MustCompile(`Snyk-Request-Id:\[([^\]]+)\]`)

	// Body humanization helpers.
	leadingTimestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+\s+`)
	htmlTagRe          = regexp.MustCompile(`<[^>]*>`)
	whitespaceRe       = regexp.MustCompile(`\s+`)
	referenceRe        = regexp.MustCompile(`(?i)Reference\s*#\s*([0-9a-fA-F.]+)`)
	permissionURLRe    = regexp.MustCompile(`(?i)access\s+"?(https?://[^"\s]+)`)
)

const maxReasonLen = 300

type httpRequest struct {
	handle, method, rawURL, snykRequestID string
	line                                  int
}

type httpResponse struct {
	handle, statusText, snykRequestID string
	status                            int
	bodyLines                         []string
	lines                             []int
	firstLine                         int
}

func (c *CorrelationCheck) Analyze(body []ParsedLine) []Finding {
	requests, responses := parseHTTPTransactions(body)
	starts := blockStartLines(requests, responses)

	used := map[string]bool{}
	seen := map[string]int{} // dedupe key -> index in findings
	var findings []Finding

	for _, resp := range responses {
		if resp.status < 400 {
			continue
		}

		reason, edge, edgeRef := humanizeBody(resp.bodyLines)
		req, correlatedBy := attributeRequest(resp, requests, used, starts)
		if req != nil {
			used[req.handle] = true
		}

		f := buildCorrelationFinding(resp, req, correlatedBy, reason, edge, edgeRef)

		key := findingDedupeKey(f)
		if idx, dup := seen[key]; dup {
			findings[idx].Lines = mergeLines(findings[idx].Lines, f.Lines)
			continue
		}
		seen[key] = len(findings)
		findings = append(findings, f)
		if len(findings) == maxHighlights {
			break
		}
	}
	return findings
}

// txnBuilder groups request/response rows by their (distinct) hex handles as the
// body is walked once, assembling multi-line response bodies.
type txnBuilder struct {
	requests    map[string]*httpRequest
	responses   map[string]*httpResponse
	reqOrder    []string
	respOrder   []string
	currentBody *httpResponse // response whose (multi-line) body is being read
}

func newTxnBuilder() *txnBuilder {
	return &txnBuilder{requests: map[string]*httpRequest{}, responses: map[string]*httpResponse{}}
}

func (b *txnBuilder) getReq(handle string) *httpRequest {
	r, ok := b.requests[handle]
	if !ok {
		r = &httpRequest{handle: handle}
		b.requests[handle] = r
		b.reqOrder = append(b.reqOrder, handle)
	}
	return r
}

func (b *txnBuilder) getResp(handle string) *httpResponse {
	r, ok := b.responses[handle]
	if !ok {
		r = &httpResponse{handle: handle}
		b.responses[handle] = r
		b.respOrder = append(b.respOrder, handle)
	}
	return r
}

func (b *txnBuilder) setSnykID(handle, id string) {
	if r, ok := b.requests[handle]; ok {
		r.snykRequestID = id
	}
	if r, ok := b.responses[handle]; ok {
		r.snykRequestID = id
	}
}

func (b *txnBuilder) feed(ln ParsedLine) {
	if !ln.HasCLIPrefix {
		// A body may continue on lines carrying only the CI runner timestamp
		// (no CLI prefix), e.g. an Akamai HTML error page.
		if b.currentBody != nil {
			b.currentBody.bodyLines = append(b.currentBody.bodyLines, stripLeadingTimestamp(ln.Message))
			b.currentBody.lines = append(b.currentBody.lines, ln.Number)
		}
		return
	}

	msg := ln.Message
	switch {
	case reqLineRe.MatchString(msg):
		m := reqLineRe.FindStringSubmatch(msg)
		r := b.getReq(m[1])
		r.method, r.rawURL = m[2], m[3]
		if r.line == 0 {
			r.line = ln.Number
		}
		b.currentBody = nil
	case respBodyRe.MatchString(msg):
		m := respBodyRe.FindStringSubmatch(msg)
		r := b.getResp(m[1])
		r.bodyLines = append(r.bodyLines, m[2])
		b.recordRespLine(r, ln.Number)
		b.currentBody = r
	case respStatusRe.MatchString(msg):
		m := respStatusRe.FindStringSubmatch(msg)
		r := b.getResp(m[1])
		if status, err := strconv.Atoi(m[2]); err == nil {
			r.status = status
		}
		r.statusText = strings.TrimSpace(m[3])
		b.recordRespLine(r, ln.Number)
		b.currentBody = nil
	case headerRe.MatchString(msg):
		handle := headerRe.FindStringSubmatch(msg)[1]
		if sm := snykIDRe.FindStringSubmatch(msg); sm != nil {
			b.setSnykID(handle, sm[1])
		}
		b.currentBody = nil
	default:
		b.currentBody = nil
	}
}

func (b *txnBuilder) recordRespLine(r *httpResponse, lineNum int) {
	r.lines = append(r.lines, lineNum)
	if r.firstLine == 0 {
		r.firstLine = lineNum
	}
}

// parseHTTPTransactions walks the body once and returns the request/response
// groups in first-seen order.
func parseHTTPTransactions(body []ParsedLine) ([]*httpRequest, []*httpResponse) {
	b := newTxnBuilder()
	for _, ln := range body {
		b.feed(ln)
	}

	requests := make([]*httpRequest, 0, len(b.reqOrder))
	for _, h := range b.reqOrder {
		requests = append(requests, b.requests[h])
	}
	responses := make([]*httpResponse, 0, len(b.respOrder))
	for _, h := range b.respOrder {
		responses = append(responses, b.responses[h])
	}
	return requests, responses
}

// attributeRequest links a response to its originating request, best-effort.
func attributeRequest(resp *httpResponse, requests []*httpRequest, used map[string]bool, starts []int) (*httpRequest, string) {
	if r := matchBySnykRequestID(resp, requests); r != nil {
		return r, "snyk-request-id"
	}
	if r := matchByBodyURL(resp, requests); r != nil {
		return r, "url"
	}
	if r := matchByAdjacency(resp, requests, used, starts); r != nil {
		return r, "adjacency"
	}
	return nil, "none"
}

// matchBySnykRequestID is confident and order-independent.
func matchBySnykRequestID(resp *httpResponse, requests []*httpRequest) *httpRequest {
	if resp.snykRequestID == "" {
		return nil
	}
	for _, r := range requests {
		if r.snykRequestID == resp.snykRequestID {
			return r
		}
	}
	return nil
}

// matchByBodyURL uses the URL an edge body reports; order-independent, used only
// when exactly one request matches the path.
func matchByBodyURL(resp *httpResponse, requests []*httpRequest) *httpRequest {
	bodyURL := extractBodyURL(resp.bodyLines)
	if bodyURL == "" {
		return nil
	}
	want := urlPath(bodyURL)
	var match *httpRequest
	for _, r := range requests {
		if r.rawURL != "" && urlPath(r.rawURL) == want {
			if match != nil {
				return nil // ambiguous: more than one request to the same path
			}
			match = r
		}
	}
	return match
}

// matchByAdjacency links the nearest preceding unpaired request, but only when
// nothing else is interleaved between it and the response (guards parallel logs).
func matchByAdjacency(resp *httpResponse, requests []*httpRequest, used map[string]bool, starts []int) *httpRequest {
	var nearest *httpRequest
	for _, r := range requests {
		if r.line > 0 && r.line < resp.firstLine && !used[r.handle] {
			if nearest == nil || r.line > nearest.line {
				nearest = r
			}
		}
	}
	if nearest == nil || interleaved(nearest.line, resp.firstLine, starts) {
		return nil
	}
	return nearest
}

func buildCorrelationFinding(resp *httpResponse, req *httpRequest, correlatedBy, reason, edge, edgeRef string) Finding {
	fields := map[string]string{
		FieldStatus:       strconv.Itoa(resp.status),
		FieldCorrelatedBy: correlatedBy,
	}
	if reason != "" {
		fields[FieldReason] = reason
	}
	if edge != "" {
		fields[FieldEdge] = edge
	}
	if edgeRef != "" {
		fields[FieldEdgeReference] = edgeRef
	}
	if resp.snykRequestID != "" {
		fields[FieldSnykRequestID] = resp.snykRequestID
	}

	headline := strings.TrimSpace(fmt.Sprintf("%d %s", resp.status, resp.statusText))
	lines := append([]int(nil), resp.lines...)
	if req != nil {
		fields[FieldMethod] = req.method
		fields[FieldURL] = req.rawURL
		fields[FieldRequestHandle] = req.handle
		if _, ok := fields[FieldSnykRequestID]; !ok && req.snykRequestID != "" {
			fields[FieldSnykRequestID] = req.snykRequestID
		}
		headline = fmt.Sprintf("%s: %s %s", headline, req.method, req.rawURL)
		if req.line > 0 {
			lines = append(lines, req.line)
		}
	}

	return Finding{
		Source:   SourceLogAnalysis,
		Kind:     KindCorrelation,
		Severity: SeverityError,
		Message:  headline,
		Lines:    sortUnique(lines),
		Fields:   fields,
	}
}

// humanizeBody turns a response body (JSON or Akamai/edge HTML) into a concise,
// human-readable reason, plus edge markers when the block came from a CDN/WAF.
func humanizeBody(bodyLines []string) (reason, edge, edgeRef string) {
	joined := strings.TrimSpace(strings.Join(bodyLines, "\n"))
	if joined == "" {
		return "", "", ""
	}
	if strings.HasPrefix(joined, "{") {
		return jsonReason(joined), "", ""
	}
	return htmlReason(joined)
}

func jsonReason(joined string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(joined), &m); err != nil {
		return ""
	}
	for _, key := range []string{"userMessage", "message", "detail", "error"} {
		if v, ok := m[key].(string); ok && v != "" {
			return truncate(v)
		}
	}
	return ""
}

func htmlReason(joined string) (reason, edge, edgeRef string) {
	decoded := html.UnescapeString(joined)
	if m := referenceRe.FindStringSubmatch(decoded); m != nil {
		edgeRef = m[1]
	}
	lower := strings.ToLower(decoded)
	if strings.Contains(lower, "access denied") || strings.Contains(lower, "edgesuite.net") ||
		strings.Contains(decoded, "AkamaiGHost") || edgeRef != "" {
		edge = "akamai"
	}

	if m := permissionURLRe.FindStringSubmatch(decoded); m != nil {
		reason = "Access Denied: no permission to access " + strings.TrimRight(m[1], `".`)
	} else {
		reason = collapseWhitespace(htmlTagRe.ReplaceAllString(decoded, " "))
	}
	if edge == "akamai" {
		if edgeRef != "" {
			reason += fmt.Sprintf(" (blocked at the edge / Akamai; Reference #%s)", edgeRef)
		} else {
			reason += " (blocked at the edge / Akamai)"
		}
	}
	return truncate(reason), edge, edgeRef
}

func extractBodyURL(bodyLines []string) string {
	decoded := html.UnescapeString(strings.Join(bodyLines, "\n"))
	if m := permissionURLRe.FindStringSubmatch(decoded); m != nil {
		return strings.TrimRight(m[1], `".`)
	}
	return ""
}

func urlPath(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '/'); j >= 0 {
			s = s[j:]
		}
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	return s
}

func interleaved(a, b int, starts []int) bool {
	for _, s := range starts {
		if s > a && s < b {
			return true
		}
	}
	return false
}

func blockStartLines(requests []*httpRequest, responses []*httpResponse) []int {
	var starts []int
	for _, r := range requests {
		if r.line > 0 {
			starts = append(starts, r.line)
		}
	}
	for _, r := range responses {
		if r.firstLine > 0 {
			starts = append(starts, r.firstLine)
		}
	}
	sort.Ints(starts)
	return starts
}

func stripLeadingTimestamp(s string) string {
	return leadingTimestampRe.ReplaceAllString(s, "")
}

func collapseWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(s, " "))
}

func truncate(s string) string {
	if len(s) <= maxReasonLen {
		return s
	}
	return s[:maxReasonLen] + "..."
}

func findingDedupeKey(f Finding) string {
	return string(f.Kind) + "|" + f.Fields[FieldMethod] + "|" + f.Fields[FieldURL] + "|" + f.Fields[FieldStatus] + "|" + f.Message
}

func mergeLines(a, b []int) []int {
	return sortUnique(append(append([]int(nil), a...), b...))
}

func sortUnique(nums []int) []int {
	if len(nums) == 0 {
		return nil
	}
	sort.Ints(nums)
	out := nums[:1]
	for _, n := range nums[1:] {
		if n != out[len(out)-1] {
			out = append(out, n)
		}
	}
	return out
}
