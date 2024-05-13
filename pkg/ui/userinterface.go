package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/utils"
)

//go:generate $GOPATH/bin/mockgen -source=userinterface.go -destination ../mocks/userinterface.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/ui/

type UserInterface interface {
	Output(output string) error
	OutputError(err error) error
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

func (ui *consoleUi) Output(output string) error {
	return utils.ErrorOf(fmt.Fprintln(ui.writer, output))
}

func (ui *consoleUi) OutputError(err error) error {
	// nothing needs to be done if err is nil
	if err == nil {
		return nil
	}

	// for simplistic handling of error catalog errors
	var snykError snyk_errors.Error
	if errors.As(err, &snykError) {
		mainPattern := "%-8s %s"
		titlePattern := "%s (%s)"
		utils.ErrorOf(fmt.Fprintln(ui.errorWriter, fmt.Sprintf(mainPattern, strings.ToUpper(snykError.Level), fmt.Sprintf(titlePattern, snykError.Title, snykError.ID))))

		if len(snykError.Detail) > 0 {
			utils.ErrorOf(fmt.Fprintln(ui.errorWriter, fmt.Sprintf(mainPattern, "", snykError.Detail)))
		}

		for _, l := range snykError.Links {
			utils.ErrorOf(fmt.Fprintln(ui.errorWriter, fmt.Sprintf(mainPattern, "", l)))
		}

		return nil
	}

	// Default handling for all other errors
	return utils.ErrorOf(fmt.Fprintln(ui.errorWriter, "Error: "+err.Error()))
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
