package ui

import (
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/snyk/go-application-framework/pkg/utils"
)

const (
	barCharacter    = "="
	currentPosition = ">"
	barWidth        = 50
	clearLine       = "\r\033[K"
)

type ProgressBar interface {
	SetProgress(progress float64) error
	Clear() error
}

func newProgressBar(writer io.Writer) *consoleProgressBar {
	return &consoleProgressBar{writer: writer}
}

type consoleProgressBar struct {
	writer io.Writer
}

func (p consoleProgressBar) SetProgress(progress float64) error {
	progress = math.Max(0, math.Min(1, progress))
	pos := int(progress * barWidth)

	_, err := fmt.Fprint(p.writer, clearLine)
	if err != nil {
		return err
	}
	barCount := int(math.Max(0, float64(barWidth-pos-1)))

	progressBar := strings.Repeat(barCharacter, pos) + currentPosition + strings.Repeat(" ", barCount)
	_, err = fmt.Fprintf(p.writer, "[%s] %3.1f%%", progressBar, progress*100)
	return err
}

func (p consoleProgressBar) Clear() error {
	return utils.ErrorOf(fmt.Fprint(p.writer, clearLine))
}
