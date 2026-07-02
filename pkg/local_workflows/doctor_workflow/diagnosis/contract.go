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
// here plus a mapping function.
const (
	SourceLogAnalysis  = "log-analysis"
	SourceCLIResult    = "cli-result"
	SourceConnectivity = "connectivity"
	SourceAuth         = "auth"
)

// Kind constants classify findings within a source.
const (
	KindHTTPError = "http-error"
	KindCLIError  = "cli-error"
	KindExitCode  = "exit-code"
	KindErrorCode = "error-code"
)

// DoctorReport is the contract type between preprocessing and inference.
type DoctorReport struct {
	SchemaVersion string    `json:"schemaVersion"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
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
// Subject is the generic "where" (log line "L448", host, env var); Code is an
// error-catalog code when present; Details/Fields hold supporting prose and
// structured key-values — not a dump of the raw log (that's Summary.Raw).
type Finding struct {
	Source      string            `json:"source"`
	Kind        string            `json:"kind"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title,omitempty"`
	Message     string            `json:"message"`
	Subject     string            `json:"subject,omitempty"`
	Code        string            `json:"code,omitempty"`
	Remediation []string          `json:"remediation,omitempty"`
	Details     []string          `json:"details,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
}
