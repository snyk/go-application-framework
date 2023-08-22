package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
)

var red = color.New(color.FgRed)

type ConsoleUiBuilder struct {
	outputWriter      io.Writer
	errorOutputWriter io.Writer
	progressWriter    io.Writer
	inputReader       *bufio.Reader
	err               error
}

func (b *ConsoleUiBuilder) WithOutputWriter(callback func(writer io.Writer) io.Writer) *ConsoleUiBuilder {
	if callback == nil {
		b.err = fmt.Errorf("nil callback for WithOutputWriter: %w", b.err)
		return b
	}
	b.outputWriter = callback(b.outputWriter)
	return b
}

func (b *ConsoleUiBuilder) WithErrorOutputWriter(callback func(writer io.Writer) io.Writer) *ConsoleUiBuilder {
	if callback == nil {
		b.err = fmt.Errorf("nil callback for WithErrorOutputWriter: %w", b.err)
		return b
	}
	b.errorOutputWriter = callback(b.errorOutputWriter)
	return b
}

func (b *ConsoleUiBuilder) WithProgressWriter(callback func(writer io.Writer) io.Writer) *ConsoleUiBuilder {
	if callback == nil {
		b.err = fmt.Errorf("nil callback for WithProgressWriter: %w", b.err)
		return b
	}
	b.progressWriter = callback(b.progressWriter)
	return b
}

func (b *ConsoleUiBuilder) WithInputReader(callback func(reader *bufio.Reader) *bufio.Reader) *ConsoleUiBuilder {
	if callback == nil {
		b.err = fmt.Errorf("nil callback for WithInputReader: %w", b.err)
		return b
	}
	b.inputReader = callback(b.inputReader)
	return b
}

func (b *ConsoleUiBuilder) Build() (UserInterface, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &consoleUi{
		writer:         b.outputWriter,
		errorWriter:    b.errorOutputWriter,
		progressWriter: b.progressWriter,
		reader:         b.inputReader,
	}, nil
}

func NewConsoleUiBuilder() *ConsoleUiBuilder {
	return &ConsoleUiBuilder{
		outputWriter:      os.Stdout,
		errorOutputWriter: newColoredWriter(os.Stdout, red),
		progressWriter:    os.Stderr,
		inputReader:       bufio.NewReader(os.Stdin),
	}
}
