package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/snyk/go-application-framework/pkg/utils"
)

type UserInterface interface {
	Output(output string) error
	OutputError(err error) error
	NewProgressBar() ProgressBar
	Input(prompt string) (string, error)
}

func DefaultUi() UserInterface {
	// Default Console UI should not have errors (this is tested in consoleui_test.go)
	return utils.ValueOf(NewConsoleUiBuilder().Build())
}

type consoleUi struct {
	writer         io.Writer
	errorWriter    io.Writer
	progressWriter io.Writer
	reader         *bufio.Reader
}

func (ui *consoleUi) Output(output string) error {
	return utils.ErrorOf(fmt.Fprintln(ui.writer, output))
}

func (ui *consoleUi) OutputError(err error) error {
	return utils.ErrorOf(fmt.Fprintln(ui.errorWriter, "Error: "+err.Error()))
}

func (ui *consoleUi) NewProgressBar() ProgressBar {
	return newProgressBar(ui.progressWriter)
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
