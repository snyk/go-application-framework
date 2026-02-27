package output_workflow

import (
	"fmt"
	"io"
)

type newLineCloser struct {
	writer  io.Writer
	written bool
}

func (wc *newLineCloser) Write(p []byte) (n int, err error) {
	wc.written = true
	return wc.writer.Write(p)
}

func (wc *newLineCloser) Close() error {
	if !wc.written {
		return nil
	}

	// template based renders had an artifact "%" at the end of the content which disappears when adding a newline
	_, err := fmt.Fprintln(wc.writer, "")
	return err
}
