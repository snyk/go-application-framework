package ui

import (
	"fmt"
	"io"
	"math"
	"strings"
)

type ProgressBar interface {
	SetProgress(progress float32) error
}

func newProgressBar(writer io.Writer) *consoleProgressBar {
	return &consoleProgressBar{writer: writer}
}

type consoleProgressBar struct {
	writer io.Writer
	title  string
}

func (p consoleProgressBar) SetProgress(progress float32) error {
	if progress < 0 {
		progress = 0
	} else if progress > 1 {
		progress = 1
	}

	const barWidth = 50
	pos := int(progress * barWidth)

	_, err := fmt.Fprint(p.writer, "\r\033[K")
	if err != nil {
		return err
	}
	if p.title != "" {
		_, err = fmt.Fprintln(p.writer, p.title)
		if err != nil {
			return err
		}
	}
	barCount := int(math.Max(0, float64(barWidth-pos-1)))

	progressBar := strings.Repeat("=", pos) + ">" + strings.Repeat(" ", barCount)
	_, err = fmt.Fprintf(p.writer, "[%s] %3.1f%%", progressBar, progress*100)
	return err
}

func (p consoleProgressBar) withTitle(title string) consoleProgressBar {
	newP := p
	newP.title = title
	return newP
}
