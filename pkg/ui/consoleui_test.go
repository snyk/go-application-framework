package ui

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/stretchr/testify/assert"
)

func Test_ProgressBar_Spinner(t *testing.T) {
	var err error
	writer := &bytes.Buffer{}

	bar := newProgressBar(writer, SpinnerType, false)
	bar.SetTitle("Hello")

	err = bar.UpdateProgress(0)
	assert.NoError(t, err)
	err = bar.UpdateProgress(0.3)
	assert.NoError(t, err)
	err = bar.UpdateProgress(1.2)
	assert.NoError(t, err)

	err = bar.Clear()
	assert.NoError(t, err)

	err = bar.UpdateProgress(1.5)
	assert.Error(t, err)

	expected := "\r[K\\   0% Hello\r[K|  30% Hello\r[K/ 100% Hello\r\u001B[K"
	assert.Equal(t, expected, writer.String())
}

func Test_ProgressBar_Spinner_Infinite(t *testing.T) {
	var err error
	writer := &bytes.Buffer{}

	bar := newProgressBar(writer, SpinnerType, false)
	bar.SetTitle("Hello")

	err = bar.UpdateProgress(InfiniteProgress)
	assert.NoError(t, err)
	err = bar.UpdateProgress(InfiniteProgress)
	assert.NoError(t, err)
	err = bar.UpdateProgress(InfiniteProgress)
	assert.NoError(t, err)

	err = bar.Clear()
	assert.NoError(t, err)

	err = bar.UpdateProgress(1.5)
	assert.Error(t, err)

	expected := "\r[K\\ Hello\r[K| Hello\r[K/ Hello\r\u001B[K"
	assert.Equal(t, expected, writer.String())
}

func Test_ProgressBar_Bar(t *testing.T) {
	var err error
	writer := &bytes.Buffer{}

	bar := newProgressBar(writer, BarType, false)
	bar.SetTitle("Hello")

	err = bar.UpdateProgress(0)
	assert.NoError(t, err)
	err = bar.UpdateProgress(0.3)
	assert.NoError(t, err)
	err = bar.UpdateProgress(1.2)
	assert.NoError(t, err)

	err = bar.Clear()
	assert.NoError(t, err)

	err = bar.UpdateProgress(1.5)
	assert.Error(t, err)

	expected := "\r\u001B[K[>                                                 ]   0% Hello\r\u001B[K[===============>                                  ]  30% Hello\r\u001B[K[=================================================>] 100% Hello\r\u001B[K"
	assert.Equal(t, expected, writer.String())
}

func Test_ProgressBar_Unknown(t *testing.T) {
	var err error
	writer := &bytes.Buffer{}

	bar := newProgressBar(writer, "Unknown", false)
	bar.SetTitle("Hello")

	err = bar.UpdateProgress(0)
	assert.NoError(t, err)
	err = bar.UpdateProgress(0.3)
	assert.NoError(t, err)
	err = bar.UpdateProgress(1.2)
	assert.NoError(t, err)

	err = bar.Clear()
	assert.NoError(t, err)

	err = bar.Clear()
	assert.NoError(t, err)

	err = bar.UpdateProgress(1.5)
	assert.Error(t, err)

	expected := "\r\u001B[K  0% Hello\r\u001B[K 30% Hello\r\u001B[K100% Hello\r\u001B[K"
	assert.Equal(t, expected, writer.String())
}

func Test_DefaultUi(t *testing.T) {
	stdin := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	name := "Hans"
	stdin.WriteString(name + "\n")

	ui := newConsoleUi(stdin, stdout, stderr)
	bar := ui.NewProgressBar()
	assert.NotNil(t, bar)

	// the bar will not render since the writer is not a TTY
	bar.SetTitle("Hello")
	err := bar.UpdateProgress(InfiniteProgress)
	assert.NoError(t, err)

	err = bar.Clear()
	assert.NoError(t, err)

	err = ui.Output("Hello")
	assert.NoError(t, err)

	in, err := ui.Input("Enter your name")
	assert.NoError(t, err)
	assert.Equal(t, name, in)

	err = ui.OutputError(fmt.Errorf("Error!"))
	assert.NoError(t, err)

	assert.Equal(t, "Hello\nEnter your name: Error!\n", stdout.String())
	assert.Equal(t, "", stderr.String())
}

func Test_DefaultUi_Html(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	stdin := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	name := "Hans"
	stdin.WriteString(name + "\n")
	ui := newConsoleUi(stdin, stdout, stderr)

	err := ui.Output("<h1>Hello</h1>")
	assert.NoError(t, err)

	in, err := ui.Input("Enter your <div class='prompt-help'>name</div>")
	assert.NoError(t, err)
	assert.Equal(t, name, in)

	err = ui.OutputError(fmt.Errorf("Error!"))
	assert.NoError(t, err)

	faint := lipgloss.NewStyle().Faint(true)
	assert.Equal(t, "Hello\nEnter your "+faint.Render("name")+": Error!\n", stdout.String())
	assert.Equal(t, "", stderr.String())
}

func Test_OutputError(t *testing.T) {
	stdin := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	ui := newConsoleUi(stdin, stdout, stderr)

	t.Run("Default error", func(t *testing.T) {
		err := fmt.Errorf("hello error world")
		uiError := ui.OutputError(err)
		assert.NoError(t, uiError)
		assert.Equal(t, err.Error()+"\n", stdout.String())
		stdout.Reset()
	})

	t.Run("Error Catalog error", func(t *testing.T) {
		err := snyk.NewBadRequestError("If you carry on like this you will ensure the wrath of OWASP, the God of Code Injection.")
		err.Links = []string{"http://example.com/docs"}

		lipgloss.SetColorProfile(termenv.TrueColor)
		uiError := ui.OutputError(err)
		assert.NoError(t, uiError)
		assert.Contains(t, stdout.String(), "ERROR")
		snaps.MatchSnapshot(t, stdout.String())
		stdout.Reset()
	})

	t.Run("Nil error", func(t *testing.T) {
		uiError := ui.OutputError(nil)
		assert.NoError(t, uiError)
		assert.Empty(t, stdout.String())
	})
}
