package diagnosis

// LogCheck is the interface for analyzers that inspect parsed log body lines.
type LogCheck interface {
	Name() string
	Analyze(body []ParsedLine) []Finding
}

// DefaultLogChecks returns the standard set of log checks. CorrelationCheck owns
// HTTP request/response findings (rich, correlated); ErrorEventCheck covers the
// remaining CLI error lines.
func DefaultLogChecks() []LogCheck {
	return []LogCheck{&CorrelationCheck{}, &ErrorEventCheck{}}
}
