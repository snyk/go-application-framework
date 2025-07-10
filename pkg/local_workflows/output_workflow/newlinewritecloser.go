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
	_, err := fmt.Fprintln(wc.writer, "")
	return err
}
