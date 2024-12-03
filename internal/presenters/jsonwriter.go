package presenters

import (
	"io"
	"regexp"
)

type JsonWriter struct {
	next             io.Writer
	regex            *regexp.Regexp
	stripWhiteSpaces bool
}

/*
 * This Writer can be used to strip away whitespaces from json content to reduce the final size
 */
func NewJsonWriter(next io.Writer, stripWhitespaces bool) io.Writer {
	return &JsonWriter{
		next:             next,
		regex:            regexp.MustCompile(`[\n\t]`),
		stripWhiteSpaces: stripWhitespaces,
	}
}

func (w *JsonWriter) Write(p []byte) (n int, err error) {
	if !w.stripWhiteSpaces {
		return w.next.Write(p)
	}

	length := len(p)
	pminus := w.regex.ReplaceAll(p, []byte(""))
	_, err = w.next.Write(pminus)
	return length, err
}
