package consoleui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/mattn/go-isatty"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/ui/uitypes"
	"github.com/snyk/go-application-framework/pkg/utils"
)

// Option is a functional option for configuring ConsoleUi.
type Option func(*ConsoleUi)

// WithInput sets the input reader.
func WithInput(in io.Reader) Option {
	return func(c *ConsoleUi) {
		c.reader = bufio.NewReader(in)
	}
}

// WithOutput sets the output writer.
func WithOutput(out io.Writer) Option {
	return func(c *ConsoleUi) {
		c.writer = out
	}
}

// WithErrorOutput sets the error output writer.
func WithErrorOutput(errWriter io.Writer) Option {
	return func(c *ConsoleUi) {
		c.errorWriter = errWriter
	}
}

// WithProgressWriter sets the progress bar writer.
func WithProgressWriter(progressWriter io.Writer) Option {
	return func(c *ConsoleUi) {
		c.progressBarFactory = func() uitypes.ProgressBar {
			if stderr, ok := progressWriter.(*os.File); ok {
				if isatty.IsTerminal(stderr.Fd()) || isatty.IsCygwinTerminal(stderr.Fd()) {
					return newProgressBar(progressWriter, SpinnerType, true)
				}
			}
			return uitypes.EmptyProgressBar{}
		}
	}
}

// New creates a new ConsoleUi with the given options.
func New(opts ...Option) *ConsoleUi {
	defaultUi := &ConsoleUi{
		writer:      os.Stdout,
		errorWriter: os.Stderr,
		reader:      bufio.NewReader(os.Stdin),
		progressBarFactory: func() uitypes.ProgressBar {
			return uitypes.EmptyProgressBar{}
		},
	}

	for _, opt := range opts {
		opt(defaultUi)
	}

	return defaultUi
}

// ConsoleUi is a console-based implementation of UserInterface.
type ConsoleUi struct {
	writer             io.Writer
	errorWriter        io.Writer
	progressBarFactory func() uitypes.ProgressBar
	reader             *bufio.Reader
}

var _ uitypes.UserInterface = (*ConsoleUi)(nil)

func (c *ConsoleUi) Output(output string) error {
	output, err := renderHtml(output)
	if err != nil {
		return err
	}

	return utils.ErrorOf(fmt.Fprintln(c.writer, output))
}

func (c *ConsoleUi) OutputError(err error, opts ...uitypes.Opts) error {
	cfg := &uitypes.UIConfig{
		Context: context.Background(),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	// nothing needs to be done if err is nil
	if err == nil {
		return nil
	}

	// for simplistic handling of error catalog errors
	var snykError snyk_errors.Error
	if errors.As(err, &snykError) {
		uiError := utils.ErrorOf(fmt.Fprintln(c.errorWriter, presenters.RenderError(snykError, cfg.Context)))
		if uiError != nil {
			return uiError
		}

		return nil
	}

	// Default handling for all other errors
	return utils.ErrorOf(fmt.Fprintln(c.errorWriter, err.Error()))
}

func (c *ConsoleUi) NewProgressBar() uitypes.ProgressBar {
	return c.progressBarFactory()
}

func (c *ConsoleUi) Input(prompt string) (string, error) {
	prompt, err := renderHtml(prompt)
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprint(c.writer, prompt, ": ")
	if err != nil {
		return "", err
	}

	input, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	// Trim spaces and newline characters
	return strings.TrimSpace(input), nil
}

func (c *ConsoleUi) SelectOptions(prompt string, options []string) (int, string, error) {
	if len(options) == 0 {
		return -1, "", fmt.Errorf("no options provided")
	}

	renderedPrompt, err := renderHtml(prompt)
	if err != nil {
		return -1, "", err
	}

	renderedOptions := make([]string, len(options))
	var renderedOpt string
	for i, opt := range options {
		renderedOpt, err = renderHtml(opt)
		if err != nil {
			return -1, "", err
		}
		renderedOptions[i] = renderedOpt
	}

	selector := promptui.Select{
		Label: renderedPrompt,
		Items: renderedOptions,
	}

	idx, _, err := selector.Run()
	if err != nil {
		return -1, "", err
	}

	if idx < 0 || idx >= len(options) {
		return -1, "", fmt.Errorf("invalid selection index: %d", idx)
	}

	return idx, options[idx], nil
}

func renderHtml(maybeHtml string) (string, error) {
	if !presenters.IsHtml(maybeHtml) {
		return maybeHtml, nil
	}

	htmlRenderer := presenters.NewHTMLPresenter(presenters.HtmlToAnsi)
	output, err := htmlRenderer.Present(maybeHtml)
	if err != nil {
		return "", err
	}

	return output, nil
}
