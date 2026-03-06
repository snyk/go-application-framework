package consoleui

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/snyk/go-application-framework/pkg/ui/uitypes"
	"github.com/snyk/go-application-framework/pkg/utils"
)

// ProgressType defines the type of progress bar.
type ProgressType string

const (
	barCharacter                 = "="
	currentPosition              = ">"
	barWidth                     = 50
	clearLine                    = "\r\033[K"
	SpinnerType     ProgressType = "spinner"
	BarType         ProgressType = "bar"
)

func newProgressBar(writer io.Writer, t ProgressType, animated bool) uitypes.ProgressBar {
	p := &consoleProgressBar{writer: writer}
	p.active.Store(true)
	p.animationRunning = false
	p.progressType = t
	p.animated = animated
	return p
}

type consoleProgressBar struct {
	writer           io.Writer
	title            string
	state            int
	progress         atomic.Pointer[float64]
	active           atomic.Bool
	animationRunning bool
	progressType     ProgressType
	animated         bool
}

func (p *consoleProgressBar) UpdateProgress(progress float64) error {
	if !p.active.Load() {
		return fmt.Errorf("progress not active")
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

func (p *consoleProgressBar) SetTitle(title string) { p.title = title }

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
