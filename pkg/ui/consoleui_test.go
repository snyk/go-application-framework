package ui_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/stretchr/testify/assert"
)

func TestDefaultBuilder_NoError(t *testing.T) {
	userInterface, err := ui.NewConsoleUiBuilder().Build()
	assert.NotNil(t, userInterface)
	assert.NoError(t, err)
}

func TestConsoleUi_Output(t *testing.T) {
	buff := &bytes.Buffer{}
	builder := ui.NewConsoleUiBuilder().WithOutputWriter(func(_ io.Writer) io.Writer {
		return buff
	})

	userInterface, err := builder.Build()
	assert.NoError(t, err)

	msg := "Hello, World!"
	err = userInterface.Output(msg)
	assert.NoError(t, err)
	assert.Equal(t, msg+"\n", buff.String())
}

func TestConsoleUi_OutputError(t *testing.T) {
	buff := &bytes.Buffer{}
	builder := ui.NewConsoleUiBuilder().WithErrorOutputWriter(func(_ io.Writer) io.Writer {
		return buff
	})

	userInterface, err := builder.Build()
	assert.NoError(t, err)

	errMsg := "sample error"
	err = userInterface.OutputError(errors.New(errMsg))
	assert.NoError(t, err)
	assert.Equal(t, "Error: "+errMsg+"\n", buff.String())
}

func TestConsoleUi_Input(t *testing.T) {
	inputMsg := "Sample Input\n"
	inputBuffer := bytes.NewBufferString(inputMsg)
	outputBuffer := &bytes.Buffer{}
	builder := ui.NewConsoleUiBuilder().
		WithInputReader(func(_ *bufio.Reader) *bufio.Reader {
			return bufio.NewReader(inputBuffer)
		}).
		WithOutputWriter(func(_ io.Writer) io.Writer {
			return outputBuffer
		})

	userInterface, err := builder.Build()
	assert.NoError(t, err)

	prompt := "Enter something"
	resp, err := userInterface.Input(prompt)
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(inputMsg), resp)
	assert.Equal(t, prompt+": ", outputBuffer.String())
}

var _ ui.ProgressBar = &fakeProgressBar{}

type fakeProgressBar struct{}

func (f fakeProgressBar) UpdateProgress(_ float64) error { return nil }
func (f fakeProgressBar) SetTitle(_ string)              {}
func (f fakeProgressBar) Clear() error                   { return nil }

func TestNewProgressBar_ReturnsCorrectProgressBar(t *testing.T) {
	customProgressBar := &fakeProgressBar{}
	builder := ui.NewConsoleUiBuilder().
		WithProgressBarGenerator(func() ui.ProgressBar {
			return customProgressBar
		})

	userInterface, err := builder.Build()
	assert.NoError(t, err)

	progressBar := userInterface.NewProgressBar()
	assert.Equal(t, customProgressBar, progressBar)
}
