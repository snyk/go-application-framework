package ui

import (
	"io"

	"github.com/fatih/color"
)

func newColoredWriter(writer io.Writer, color *color.Color) io.Writer {
	return coloredWriter{writer: writer, color: color}
}

type coloredWriter struct {
	writer io.Writer
	color  *color.Color
}

func (w coloredWriter) Write(p []byte) (n int, err error) {
	n, err = w.color.Fprint(w.writer, string(p))
	return n, err
}
