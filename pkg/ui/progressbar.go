package ui

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/snyk/go-application-framework/pkg/utils"
)

//go:generate $GOPATH/bin/mockgen -source=progressbar.go -destination ../mocks/progressbar.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/ui/

type ProgressType string

const (
	barCharacter                  = "="
	currentPosition               = ">"
	barWidth                      = 50
	clearLine                     = "\r\033[K"
	InfiniteProgress              = -1.0 // use UpdateProgress(InfiniteProgress) to show progress without setting a percentage
	SpinnerType      ProgressType = "spinner"
	BarType          ProgressType = "bar"
)

// ProgressBar is an interface for interacting with some visual progress-bar.
// It is used to show the progress of some running task (or multiple).
// Example (Infinite Progress without a value):
//
//	pBar := ui.DefaultUi().NewProgressBar("CLI Downloader")
//	defer pBar.Clear()
//	pBar.SetMessage("Downloading...")
//	_ = pBar.UpdateProgress(ui.InfiniteProgress)
//
// Example (with a value):
//
//	pBar := ui.DefaultUi().NewProgressBar("CLI Downloader")
//	defer pBar.Clear()
//	pBar.SetMessage("Downloading...")
//	for i := 0; i <= 50; i++ {
//	    pBar.UpdateProgress(float64(i) / 100.0)
//	    time.Sleep(time.Millisecond * 50)
//	}
//
//	pBar.SetMessage("Installing...")
//	for i := 50; i <= 100; i++ {
//	    pBar.UpdateProgress(float64(i) / 100.0)
//	    time.Sleep(time.Millisecond * 50)
//	}
//
// The message can be changed in the middle of the progress bar.
// In some implementations no progress bar will be shown until the first UpdateProgress is called.
type ProgressBar interface {
	// UpdateProgress updates the state of the progress bar.
	// The argument `progress` should be a float64 between 0 and 1,
	// where 0 represents 0% completion, and 1 represents 100% completion.
	// Returns an error if the update operation fails.
	UpdateProgress(progress float64) error

	// SetMessage sets the message of the progress bar, which is displayed next to the bar.
	// The message is displayed alongside the title passed in by `NewProgressBar(title string)`.
	// The message provides context or description for the operation that is being tracked.
	// Set to "" to clear the message.
	SetMessage(message string)

	// Clear removes the progress bar from the user interface.
	// Returns an error if the clearing operation fails.
	Clear() error
}

type emptyProgressBar struct{}

func (emptyProgressBar) UpdateProgress(float64) error { return nil }
func (emptyProgressBar) SetMessage(string)            {}
func (emptyProgressBar) Clear() error                 { return nil }

func newProgressBar(writer io.Writer, title string, t ProgressType, animated bool) *consoleProgressBar {
	p := &consoleProgressBar{
		writer: writer,
		title:  title,
	}
	p.active.Store(true)
	p.animationRunning = false
	p.progressType = t
	p.animated = animated
	return p
}

type consoleProgressBar struct {
	writer           io.Writer
	title            string
	message          string
	state            int
	progress         atomic.Pointer[float64]
	active           atomic.Bool
	animationRunning bool
	progressType     ProgressType
	animated         bool
}

func (p *consoleProgressBar) UpdateProgress(progress float64) error {
	if !p.active.Load() {
		return fmt.Errorf("progress bar not active")
	}

	p.progress.Store(&progress)

	if !p.animationRunning && p.animated {
		p.animationRunning = true
		go p.update()
	} else if !p.animated {
		p.update()
	}

	return nil
}

func (p *consoleProgressBar) SetMessage(message string) { p.message = message }

func (p *consoleProgressBar) Clear() error {
	if !p.active.Load() {
		return nil
	}
	p.active.Store(false)
	return utils.ErrorOf(fmt.Fprint(p.writer, clearLine))
}

func (p *consoleProgressBar) update() {
	// wait a second before starting to render progress, this will avoid showing progress for short events
	if !p.animated {
		time.Sleep(1 * time.Second)
	}

	var err error
	for {
		if !p.active.Load() {
			break
		}

		var progressString string
		progress := *p.progress.Load()
		if progress >= 0 {
			progress = math.Max(0, math.Min(1, progress))
			progressString = fmt.Sprintf("%3.0f%% ", progress*100)
		}

		if len(p.title) > 0 {
			progressString += p.title
			if len(p.message) > 0 {
				progressString += " - "
			}
		}
		if len(p.message) > 0 {
			progressString += p.message
		}

		p.state++

		if p.progressType == SpinnerType {
			err = p.renderSpinner(progressString)
		} else if p.progressType == BarType {
			err = p.renderBar(progressString)
		} else {
			err = p.renderText(progressString)
		}

		if err != nil || !p.animated {
			break
		}

		time.Sleep(250 * time.Millisecond)
	}
}

func (p *consoleProgressBar) renderSpinner(progressString string) error {
	elementSet := []string{"-", "\\", "|", "/"}
	progressElement := elementSet[p.state%len(elementSet)]
	text := fmt.Sprint(progressElement, " ", progressString)
	return p.renderText(text)
}

func (p *consoleProgressBar) renderBar(progressString string) error {
	progress := *p.progress.Load()

	// infinite bar, using state and wrapping around at the end
	if progress < 0 {
		progress = float64((p.state*2)%100) / 100
	}

	pos := int(math.Min(progress*barWidth, barWidth-1))
	barCount := int(math.Max(0, float64(barWidth-pos-1)))
	progressBar := strings.Repeat(barCharacter, pos) + currentPosition + strings.Repeat(" ", barCount)
	text := fmt.Sprint("[", progressBar, "] ", progressString)
	return p.renderText(text)
}

func (p *consoleProgressBar) renderText(progressString string) error {
	_, err := fmt.Fprint(p.writer, clearLine)
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(p.writer, progressString)
	if err != nil {
		return err
	}

	return nil
}
