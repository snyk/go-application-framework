package diagnosis

// Severity classifies the urgency of a Finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
)

// Source constants identify where a finding originated.
const (
	SourceLogAnalysis = "log-analysis"
	SourceCLIResult   = "cli-result"
)

// Kind constants classify findings.
const (
	KindHTTPError = "http-error"
	KindCLIError  = "cli-error"
	KindExitCode  = "exit-code"
	KindErrorCode = "error-code"
)

// DoctorReport is the contract type between preprocessing and inference.
type DoctorReport struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
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

// Finding represents a single diagnostic observation.
type Finding struct {
	Source   string   `json:"source"`
	Line     int      `json:"line,omitempty"`
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}
