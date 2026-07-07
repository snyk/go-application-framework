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

// Producer identifies which check emitted a finding (its origin); downstream
// groups by this label without importing the producer's types. A new producer
// adds a constant here plus a mapping function. Typed (like Severity) so
// producers cannot invent arbitrary values. Distinct from the report-level
// SourceInfo, which is the analyzed input.
type Producer string

const (
	ProducerLogAnalysis  Producer = "log-analysis"
	ProducerCLIResult    Producer = "cli"
	ProducerConnectivity Producer = "connectivity"
	ProducerAuth         Producer = "authentication"
	ProducerEnvironment  Producer = "environment"
	ProducerConfig       Producer = "configuration"
)

// Kind classifies the specific category of a finding (what it is), orthogonal to
// its Producer (who emitted it). Typed so producers use these constants instead
// of free-form strings.
type Kind string

const (
	KindHTTPError   Kind = "http-error"
	KindCLIError    Kind = "cli-error"
	KindExitCode    Kind = "exit-code"
	KindErrorCode   Kind = "error-code"
	KindCorrelation Kind = "correlation" // request<->response correlation

	// Live-check outcomes. Distinct from their Producer so Kind is not redundant.
	KindAuthOK              Kind = "auth-ok"
	KindAuthFailure         Kind = "auth-failure"
	KindConnectivityOK      Kind = "connectivity-ok"
	KindConnectivityFailure Kind = "connectivity-failure"
	KindCacheOK             Kind = "cache-ok"
	KindCacheFailure        Kind = "cache-failure"
	KindConfigOK            Kind = "config-ok"
	KindConfigCheck         Kind = "config-check"
)

// Well-known Finding.Fields keys. Centralized so producers and consumers
// (presentation, LLM) agree on names rather than duplicating string literals.
const (
	FieldMethod        = "method"
	FieldURL           = "url"
	FieldStatus        = "status"
	FieldSnykRequestID = "snykRequestId"
	FieldEdge          = "edge"          // e.g. "akamai" when blocked at the edge
	FieldEdgeReference = "edgeReference" // edge/CDN reference id
	FieldCorrelatedBy  = "correlatedBy"  // how the request was linked: snyk-request-id | url | adjacency | none
)

const (
	SourceKindLogFile = "log-file"
	SourceKindStdin   = "stdin"
	SourceKindLive    = "live"
)

// DoctorReport is the contract type between preprocessing and inference.
type DoctorReport struct {
	SchemaVersion string    `json:"schemaVersion"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
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
	Producer    Producer          `json:"producer"`
	Kind        Kind              `json:"kind"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title,omitempty"`
	Message     string            `json:"message"`
	Subject     string            `json:"subject,omitempty"`
	Lines       []int             `json:"lines,omitempty"`
	Code        string            `json:"code,omitempty"`
	Details     []string          `json:"details,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
}
