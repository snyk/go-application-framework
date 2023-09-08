package ui

import (
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/snyk/go-application-framework/pkg/utils"
)

//go:generate $GOPATH/bin/mockgen -source=progressbar.go -destination ../mocks/progressbar.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/ui/

const (
	barCharacter    = "="
	currentPosition = ">"
	barWidth        = 50
	clearLine       = "\r\033[K"
)

// ProgressBar is an interface for interacting with some visual progress-bar.
// It is used to show the progress of some running task (or multiple).
// Example:
//
//	var pBar ProgressBar = ui.DefaultUi().NewProgressBar(os.Stdout)
//	pBar.SetTitle("Downloading...")
//	for i := 0; i <= 100; i++ {
//	    pBar.UpdateProgress(float64(i) / 100.0)
//	    time.Sleep(time.Millisecond * 50)
//	}
//	pBar.Clear()
//
// Calling `Clear()` is not required, but the caret will remain at the end of the progress bar, so a linebreak is required.
// Example:
//
//	var pBar ProgressBar = ui.DefaultUi().NewProgressBar(os.Stdout)
//	pBar.SetTitle("Downloading...")
//	for i := 0; i <= 100; i++ {
//	    pBar.UpdateProgress(float64(i) / 100.0)
//	    time.Sleep(time.Millisecond * 50)
//	}
//	fmt.Println()
//
// The title can be changed in the middle of the progress bar, but it will not be visible until the next update.
type ProgressBar interface {
	// UpdateProgress updates the state of the progress bar.
	// The argument `progress` should be a float64 between 0 and 1,
	// where 0 represents 0% completion, and 1 represents 100% completion.
	// Returns an error if the update operation fails.
	UpdateProgress(progress float64) error

	// SetTitle sets the title of the progress bar, which is displayed next to the bar.
	// The title provides context or description for the operation that is being tracked.
	SetTitle(title string)

	// Clear removes the progress bar from the terminal.
	// Returns an error if the clearing operation fails.
	Clear() error
}

func newProgressBar(writer io.Writer) *consoleProgressBar {
	return &consoleProgressBar{writer: writer}
}

type consoleProgressBar struct {
	writer io.Writer
	title  string
}

func (p *consoleProgressBar) UpdateProgress(progress float64) error {
	progress = math.Max(0, math.Min(1, progress))
	pos := int(progress * barWidth)

	_, err := fmt.Fprint(p.writer, clearLine)
	if err != nil {
		return err
	}
	barCount := int(math.Max(0, float64(barWidth-pos-1)))

	progressBar := strings.Repeat(barCharacter, pos) + currentPosition + strings.Repeat(" ", barCount)
	_, err = fmt.Fprint(p.writer, "[", progressBar, "] ", fmt.Sprintf("%3.1f", progress*100), "% ", p.title)
	return err
}

func (p *consoleProgressBar) SetTitle(title string) { p.title = title }

func (p *consoleProgressBar) Clear() error {
	return utils.ErrorOf(fmt.Fprint(p.writer, clearLine))
}
