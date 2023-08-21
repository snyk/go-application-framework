package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/snyk/go-application-framework/pkg/utils"
)

type UserInterface interface {
	Output(output string) error
	OutputError(err error) error
	NewProgressBar() ProgressBar
	Input(prompt string) (string, error)
}

var red = color.New(color.FgRed)

func NewConsoleUi() UserInterface {
	return &consoleUi{
		writer: os.Stdout,
		reader: bufio.NewReader(os.Stdin),
	}
}

type consoleUi struct {
	writer io.Writer
	reader *bufio.Reader
}

func (ui *consoleUi) Output(output string) error {
	return utils.ErrorOf(fmt.Fprintln(ui.writer, output))
}

func (ui *consoleUi) OutputError(err error) error {
	return utils.ErrorOf(red.Fprintln(ui.writer, "Error: "+err.Error()))
}

func (ui *consoleUi) NewProgressBar() ProgressBar {
	return newProgressBar(ui.writer)
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
