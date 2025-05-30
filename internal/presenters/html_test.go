package presenters

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/assert"
)

func Test_IsValidHtml(t *testing.T) {
	testCases := []struct {
		desc string
		html string
		want bool
	}{
		{
			desc: "valid - single html tag",
			html: "hello</div>",
			want: true,
		},
		{
			desc: "valid - with text outside tag",
			html: "<div>hello</div> world",
			want: true,
		},
		{
			desc: "valid - with attributes",
			html: "<div class='classed' aria-value selected>hello<div>",
			want: true,
		},
		{
			desc: "valid - multiple tags",
			html: "<div>hello</div><div>world</div>",
			want: true,
		},
		{
			desc: "invalid - does not contain < and >",
			html: "some text",
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := IsHtml(tc.html)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_HTMLpresenter_Present(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	faint := lipgloss.NewStyle().Faint(true)

	callback := func(tag, cssClass, originalContent string) string {
		output := originalContent
		if tag == "pre" {
			output = originalContent + "\n"
		}

		if cssClass == "red" {
			output = red.Render(originalContent)
		}

		return output
	}

	testCases := []struct {
		name           string
		html           string
		callback       ElementCallback
		expectedOutput string
	}{
		{
			name:           "outputs the orignal text (no tags) if no callback is supplied",
			html:           "<div>hello</div>",
			callback:       nil,
			expectedOutput: "hello",
		},
		{
			name:           "applies callback operations",
			html:           "<div class='red'>hello</div>",
			callback:       callback,
			expectedOutput: red.Render("hello"),
		},
		{
			name:           "applies callbacks to nested children",
			html:           "<div>hi<p class='red'>hello</p>hola</div>",
			callback:       callback,
			expectedOutput: "hi " + red.Render("hello") + "hola",
		},
		{
			name:           "applies spacing betweeen block elements",
			html:           "<div>hello</div><div>world</div>",
			callback:       callback,
			expectedOutput: "hello world",
		},
		{
			name:           "html-to-ansi - applies styling to the class target",
			html:           "<div class='prompt-help'>something</div>",
			callback:       HtmlToAnsi,
			expectedOutput: faint.Render("something"),
		},
		{
			name:           "html-to-ansi - does not apply styling if the class is not present",
			html:           "<div>something</div>",
			callback:       HtmlToAnsi,
			expectedOutput: "something",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			presenter := NewHTMLPresenter(tc.callback)
			got, err := presenter.Present(tc.html)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, got)
		})
	}
}
