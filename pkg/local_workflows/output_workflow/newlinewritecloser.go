package output_workflow

import (
	"fmt"
	"io"
)

type newLineCloser struct {
	writer io.Writer
}

func (wc *newLineCloser) Write(p []byte) (n int, err error) {
	return wc.writer.Write(p)
}

func (wc *newLineCloser) Close() error {
	// template based renders had an artifact "%" at the end of the content which disappears when adding a newline
	_, err := fmt.Fprintln(wc.writer, "")
	return err
}
