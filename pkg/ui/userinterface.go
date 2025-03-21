package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/internal/presenters"

	"github.com/snyk/go-application-framework/pkg/utils"
)

//go:generate $GOPATH/bin/mockgen -source=userinterface.go -destination ../mocks/userinterface.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/ui/

type UserInterface interface {
	Output(output interface{}) error
	OutputError(err error, opts ...Opts) error
	NewProgressBar() ProgressBar
	Input(prompt string) (string, error)
}

func DefaultUi() UserInterface {
	return newConsoleUi(os.Stdin, os.Stdout, os.Stderr)
}

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

type uiConfig struct {
	//nolint:containedctx // internal struct used to maintain backwards compatibility
	context context.Context
}

type Opts = func(ui *uiConfig)

func WithContext(ctx context.Context) Opts {
	return func(ui *uiConfig) {
		ui.context = ctx
	}
}

func (ui *consoleUi) Output(output interface{}) error {

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
	_, err := fmt.Fprint(ui.writer, prompt, ": ")
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
