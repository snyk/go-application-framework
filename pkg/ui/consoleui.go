package ui

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
	"github.com/snyk/go-application-framework/pkg/utils"
)

func newConsoleUi(in io.Reader, out io.Writer, err io.Writer) UserInterface {
	// Default Console UI should not have errors (this is tested in consoleui_test.go)
	defaultUi := &consoleUi{
		writer:      out,
		errorWriter: out,
		reader:      bufio.NewReader(in),
	}

	defaultUi.progressBarFactory = func() ProgressBar {
		if stderr, ok := err.(*os.File); ok {
			if isatty.IsTerminal(stderr.Fd()) || isatty.IsCygwinTerminal(stderr.Fd()) {
				return newProgressBar(err, SpinnerType, true)
			}
		}

		return emptyProgressBar{}
	}

	return defaultUi
}

type consoleUi struct {
	writer             io.Writer
	errorWriter        io.Writer
	progressBarFactory func() ProgressBar
	reader             *bufio.Reader
}

func (ui *consoleUi) Output(output string) error {
	output, err := renderHtml(output)
	if err != nil {
		return err
	}

	return utils.ErrorOf(fmt.Fprintln(ui.writer, output))
}

func (ui *consoleUi) OutputError(err error, opts ...Opts) error {
	uiConfig := &uiConfig{
		context: context.Background(),
	}
	for _, opt := range opts {
		opt(uiConfig)
	}
	// nothing needs to be done if err is nil
	if err == nil {
		return nil
	}

	// for simplistic handling of error catalog errors
	var snykError snyk_errors.Error
	if errors.As(err, &snykError) {
		uiError := utils.ErrorOf(fmt.Fprintln(ui.errorWriter, presenters.RenderError(snykError, uiConfig.context)))
		if uiError != nil {
			return uiError
		}

		return nil
	}

	// Default handling for all other errors
	return utils.ErrorOf(fmt.Fprintln(ui.errorWriter, err.Error()))
}

func (ui *consoleUi) NewProgressBar() ProgressBar {
	return ui.progressBarFactory()
}

func (ui *consoleUi) Input(prompt string) (string, error) {
	prompt, err := renderHtml(prompt)
	if err != nil {
		return "", err
	}

	_, err = fmt.Fprint(ui.writer, prompt, ": ")
	if err != nil {
		return "", err
	}

	input, err := ui.reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	// Trim spaces and newline characters
	return strings.TrimSpace(input), nil
}

func (ui *consoleUi) SelectOptions(prompt string, options []string) (int, string, error) {
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
