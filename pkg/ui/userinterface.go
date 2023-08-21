package ui

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/snyk/go-application-framework/pkg/utils"
)

type UserInterface interface {
	Output(output string) error
	OutputError(err error) error
	ProgressBar() ProgressBar
}

var red = color.New(color.FgRed)

func NewConsoleUi() UserInterface {
	return &consoleUi{writer: os.Stdout}
}

type consoleUi struct {
	writer io.Writer
}

func (ui *consoleUi) Output(output string) error {
	return utils.ErrorOf(fmt.Fprintln(ui.writer, output))
}

func (ui *consoleUi) OutputError(err error) error {
	return utils.ErrorOf(red.Fprintln(ui.writer, "Error: "+err.Error()))
}

func (ui *consoleUi) ProgressBar() ProgressBar {
	return newProgressBar(ui.writer)
}
