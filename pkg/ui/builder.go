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
	outputWriter       io.Writer
	errorOutputWriter  io.Writer
	inputReader        *bufio.Reader
	err                error
	progressBarFactory func() ProgressBar
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

func (b *ConsoleUiBuilder) WithInputReader(callback func(reader *bufio.Reader) *bufio.Reader) *ConsoleUiBuilder {
	if callback == nil {
		b.err = fmt.Errorf("nil callback for WithInputReader: %w", b.err)
		return b
	}
	b.inputReader = callback(b.inputReader)
	return b
}

func (b *ConsoleUiBuilder) WithProgressBarGenerator(generator func() ProgressBar) *ConsoleUiBuilder {
	if generator == nil {
		b.err = fmt.Errorf("nil generator for WithProgressBarGenerator: %w", b.err)
		return b
	}
	b.progressBarFactory = generator
	return b
}

func (b *ConsoleUiBuilder) Build() (UserInterface, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &consoleUi{
		writer:             b.outputWriter,
		errorWriter:        b.errorOutputWriter,
		progressBarFactory: b.progressBarFactory,
		reader:             b.inputReader,
	}, nil
}

func NewConsoleUiBuilder() *ConsoleUiBuilder {
	return &ConsoleUiBuilder{
		outputWriter:       os.Stdout,
		errorOutputWriter:  newColoredWriter(os.Stdout, red),
		progressBarFactory: func() ProgressBar { return newProgressBar(os.Stderr) },
		inputReader:        bufio.NewReader(os.Stdin),
	}
}
