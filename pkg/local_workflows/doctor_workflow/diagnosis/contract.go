package diagnosis

// SchemaVersion stamps the DoctorReport shape so consumers of the --json
// artifact can detect incompatibility. Bump only on breaking changes (field
// removed/renamed/retyped); additive omitempty fields don't bump.
//
// TODO(doctor): once the shape stabilizes and an external consumer needs to
// validate, graduate to a frozen JSON Schema + SchemaForVersion selector.
const SchemaVersion = "1"

// Severity classifies the urgency of a Finding. A string (not iota) so the JSON
// is self-documenting and shared across producers.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Source identifies which producer emitted a finding; downstream groups by this
// label without importing the producer's types. A new producer adds a constant
// here plus a mapping function. Typed (like Severity) so producers cannot invent
// arbitrary values.
type Source string

const (
	SourceLogAnalysis  Source = "log-analysis"
	SourceCLIResult    Source = "cli-result"
	SourceConnectivity Source = "connectivity"
	SourceAuth         Source = "auth"
)

// Kind classifies a finding within a Source. Typed so producers use these
// constants instead of free-form strings.
type Kind string

const (
	KindHTTPError    Kind = "http-error"
	KindCLIError     Kind = "cli-error"
	KindExitCode     Kind = "exit-code"
	KindErrorCode    Kind = "error-code"
	KindCorrelation  Kind = "correlation"    // request<->response correlation
	KindAuth         Kind = "authentication" // live auth check
	KindConnectivity Kind = "connectivity"   // live connectivity check
)

// Well-known Finding.Fields keys. Centralized so producers and consumers
// (presentation, LLM) agree on names rather than duplicating string literals.
const (
	FieldMethod        = "method"
	FieldURL           = "url"
	FieldStatus        = "status"
	FieldSnykRequestID = "snykRequestId"
	FieldRequestHandle = "requestHandle"
	FieldReason        = "reason"
	FieldEdge          = "edge"          // e.g. "akamai" when blocked at the edge
	FieldEdgeReference = "edgeReference" // edge/CDN reference id
	FieldCorrelatedBy  = "correlatedBy"  // how the request was linked: snyk-request-id | url | adjacency | none
)

// SourceInfo records what was analyzed. Kind is one of the SourceKind* constants.
type SourceInfo struct {
	Kind string `json:"kind"`
	Path string `json:"path,omitempty"`
}

const (
	SourceKindLogFile = "log-file"
	SourceKindStdin   = "stdin"
	SourceKindLive    = "live"
)

// DoctorReport is the contract type between preprocessing and inference.
type DoctorReport struct {
	SchemaVersion string      `json:"schemaVersion"`
	Source        *SourceInfo `json:"source,omitempty"`
	Summary       Summary     `json:"summary"`
	Findings      []Finding   `json:"findings"`
	// Result is the CLI's result/errors block kept verbatim, preserving detail
	// (Description/Links/Requests) that Findings don't capture. Mirrors
	// Summary.Raw for the footer.
	Result string `json:"result,omitempty"`
}

// Summary holds the parsed environment/header section of a debug log.
type Summary struct {
	Fields []KeyValue `json:"fields"`
	Raw    string     `json:"raw,omitempty"`
}

// KeyValue is a single key-value pair from the log header.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Finding is a producer-agnostic diagnostic observation: any producer (log,
// connectivity, auth) maps into it and downstream reads only these fields.
// Subject is the generic "where" (log line "L448", host, env var); Lines are the
// structured source line numbers a finding spans (traceable + supports
// correlation); Code is an error-catalog code when present; Details/Fields hold
// supporting prose and structured key-values - not a dump of the raw log (that's
// Summary.Raw).
type Finding struct {
	Source      Source            `json:"source"`
	Kind        Kind              `json:"kind"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title,omitempty"`
	Message     string            `json:"message"`
	Subject     string            `json:"subject,omitempty"`
	Lines       []int             `json:"lines,omitempty"`
	Code        string            `json:"code,omitempty"`
	Remediation []string          `json:"remediation,omitempty"`
	Details     []string          `json:"details,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
}
