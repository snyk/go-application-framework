package diagnosis

// LogCheck is the interface for analyzers that inspect parsed log body lines.
type LogCheck interface {
	Name() string
	Analyze(body []ParsedLine) []Finding
}

// DefaultLogChecks returns the standard set of log checks.
func DefaultLogChecks() []LogCheck {
	return []LogCheck{&ErrorEventCheck{}}
}
