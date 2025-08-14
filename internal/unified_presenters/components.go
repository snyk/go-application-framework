package unified_presenters

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/networking"
)

const (
	// SnykDocsURL is the base URL for Snyk's documentation.
	SnykDocsURL = "https://docs.snyk.io"
	// SnykDocsErrorCatalogPath is the path to the error catalog on Snyk's documentation website.
	SnykDocsErrorCatalogPath = "/scan-with-snyk/error-catalog"
	docsLabel                = "Docs:"
)

const valueStyleWidth = 80

func errorLevelToStyle(errLevel string) lipgloss.Style {
	style := lipgloss.NewStyle().
		PaddingLeft(1).
		PaddingRight(1).
		Background(lipgloss.Color("1")).
		Foreground(lipgloss.Color("15"))

	if errLevel == "warn" {
		style.
			Background(lipgloss.Color("3")).
			Foreground(lipgloss.Color("0"))
	}

	return style
}

// RenderError renders a snyk_errors.Error to a string.
func RenderError(ctx context.Context, err *snyk_errors.Error) string {
	var body []string

	level := strings.ToUpper(err.Level)
	backgroundHighlight := errorLevelToStyle(err.Level)
	label := lipgloss.NewStyle().Width(8)
	value := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)

	if err.Description != "" {
		desc := err.Description
		re := regexp.MustCompile(`\n+`)
		lines := re.Split(desc, -1)

		if len(lines) > 1 {
			lines = lines[0:2]
			for i, l := range lines {
				lines[i] = strings.Trim(l, " \n")
			}
			desc = strings.Join(lines, " ")
		}

		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render(""),
			value.Copy().Width(valueStyleWidth).Render(desc),
		))
	}

	if err.Detail != "" {
		detailValue := lipgloss.NewStyle().PaddingLeft(3).PaddingRight(1)
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("\n"),
			detailValue.Copy().Width(valueStyleWidth).Render("\n"+err.Detail),
		))
	}

	if err.Detail != "" || err.Description != "" {
		body = append(body, "")
	}

	title := strings.TrimSpace(err.Title)
	if err.ErrorCode != "" {
		fragment := "#" + strings.ToLower(err.ErrorCode)
		link := SnykDocsURL + SnykDocsErrorCatalogPath + fragment
		err.Links = append([]string{link}, err.Links...)
		title += fmt.Sprintf(" (%s)", err.ErrorCode)
	}

	if err.StatusCode > http.StatusOK {
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Status:"),
			value.Render(strconv.Itoa(err.StatusCode)+" "+http.StatusText(err.StatusCode)),
		))
	}

	if len(err.Links) > 0 {
		link := err.Links[0] + "\n"
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render(docsLabel),
			value.Render(link),
		))
	}

	if v := ctx.Value(networking.InteractionIdKey); v != nil {
		interactionID, ok := v.(string)
		if ok {
			body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
				label.Render("ID:"),
				value.Render(interactionID),
			))
		}
	}

	title = renderBold(title)

	return "\n" + backgroundHighlight.MarginRight(6-len(level)).Render(level) + " " + title + "\n" +
		strings.Join(body, "\n")
}

// RenderLink renders a string as a hyperlink.
func RenderLink(str string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")).
		Render(str)
}

// RenderDivider renders a horizontal line.
func RenderDivider() string {
	return "─────────────────────────────────────────────────────\n"
}

// RenderTitle renders a string as a title.
func RenderTitle(str string) string {
	return fmt.Sprintf("\n%s\n\n", renderBold(str))
}

// RenderTip renders a string as a tip.
func RenderTip(str string) string {
	body := lipgloss.NewStyle().
		PaddingLeft(3)
	return fmt.Sprintf("\n💡 Tip\n\n%s", body.Render(str))
}

// FilterSeverityASC filters a slice of severities based on a minimum level.
func FilterSeverityASC(original []string, severityMinLevel string) []string {
	if severityMinLevel == "" {
		return original
	}

	minLevelPointer := slices.Index(original, severityMinLevel)

	if minLevelPointer >= 0 {
		return original[minLevelPointer:]
	}

	return original
}
