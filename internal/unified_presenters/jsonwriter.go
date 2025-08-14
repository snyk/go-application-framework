package unified_presenters

import (
	"fmt"
	"io"
	"regexp"
)

// JSONWriter is a writer that can optionally strip whitespaces from JSON output.
type JSONWriter struct {
	next             io.Writer
	regex            *regexp.Regexp
	stripWhiteSpaces bool
}

// NewJSONWriter creates a new JSON writer that can optionally strip whitespaces.
//
//nolint:ireturn // expected to return an interface for flexibility
func NewJSONWriter(next io.Writer, stripWhitespaces bool) io.Writer {
	return &JSONWriter{
		next:             next,
		regex:            regexp.MustCompile(`[\n\t]`),
		stripWhiteSpaces: stripWhitespaces,
	}
}

func (w *JSONWriter) Write(p []byte) (n int, err error) {
	if !w.stripWhiteSpaces {
		n, writeErr := w.next.Write(p)
		if writeErr != nil {
			return n, fmt.Errorf("failed to write to writer: %w", writeErr)
		}
		return n, nil
	}

	length := len(p)
	pminus := w.regex.ReplaceAll(p, []byte(""))
	_, writeErr := w.next.Write(pminus)
	if writeErr != nil {
		return length, fmt.Errorf("failed to write to writer: %w", writeErr)
	}
	return length, nil
}
