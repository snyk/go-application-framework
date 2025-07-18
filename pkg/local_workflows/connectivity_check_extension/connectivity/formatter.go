package connectivity

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/ui"
)

// Formatter formats connectivity check results using GAF UI components
type Formatter struct {
	ui       ui.UserInterface
	useColor bool
}

// output is a helper method that calls ui.Output and ignores errors
// since UI output errors are non-critical for this formatter
func (f *Formatter) output(str string) {
	_ = f.ui.Output(str) //nolint:errcheck // UI output errors are non-critical
}

// NewFormatter creates a new formatter using GAF UI interfaces
func NewFormatter(ui ui.UserInterface, useColor bool) *Formatter {
	if useColor {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	return &Formatter{
		ui:       ui,
		useColor: useColor,
	}
}

// FormatResult formats the complete connectivity check result using GAF presenters
func (f *Formatter) FormatResult(result *ConnectivityCheckResult) error {
	if err := f.formatProxyConfig(result.ProxyConfig); err != nil {
		return err
	}

	f.output("")

	f.output(f.renderHTML(`<h2 class="section-title">Testing connectivity to Snyk endpoints...</h2>`))
	f.output("")

	f.output(fmt.Sprintf("%-30s %s", "Host", "Result"))
	f.output(presenters.RenderDivider())

	for _, hostResult := range result.HostResults {
		if err := f.formatHostResult(hostResult); err != nil {
			return err
		}
	}

	if err := f.formatTODOs(result.TODOs); err != nil {
		return err
	}

	if result.TokenPresent || result.OrgCheckError != nil {
		return f.formatOrganizations(result)
	}

	return nil
}

// formatProxyConfig formats proxy configuration information
func (f *Formatter) formatProxyConfig(config ProxyConfig) error {
	f.output("Checking for proxy configuration...")
	f.output("")
	f.output("Environment variables:")

	proxyVars := []struct {
		name  string
		value string
	}{
		{"HTTPS_PROXY", getEnvOrEmpty("HTTPS_PROXY")},
		{"https_proxy", getEnvOrEmpty("https_proxy")},
		{"HTTP_PROXY", getEnvOrEmpty("HTTP_PROXY")},
		{"http_proxy", getEnvOrEmpty("http_proxy")},
		{"NO_PROXY", getEnvOrEmpty("NO_PROXY")},
		{"no_proxy", getEnvOrEmpty("no_proxy")},
	}

	for _, pv := range proxyVars {
		if pv.value != "" {
			f.output(fmt.Sprintf("  %-12s %s", pv.name+":", f.renderHTML(fmt.Sprintf(`<span class="warning">%s</span>`, pv.value))))
		} else {
			f.output(fmt.Sprintf("  %-12s %s", pv.name+":", f.renderHTML(`<span class="prompt-help">(not set)</span>`)))
		}
	}

	f.output("")
	if config.Detected {
		f.output(f.renderHTML(fmt.Sprintf(`<span class="success">✓ Proxy detected</span> via <span class="warning">%s</span>: <span class="warning">%s</span>`,
			config.Variable, config.URL)))
		f.output("Testing connectivity through proxy...")
	} else {
		f.output(f.renderHTML(`<span class="info">ℹ No proxy detected</span> - Testing direct connection...`))
	}

	return nil
}

// formatHostResult formats a single host result
func (f *Formatter) formatHostResult(result HostResult) error {
	line := fmt.Sprintf("%-30s ", result.DisplayHost)

	statusStr := result.Status.String()
	if result.StatusCode > 0 {
		statusStr = fmt.Sprintf("%s (HTTP %d)", statusStr, result.StatusCode)
	}

	// Format based on status
	switch result.Status {
	case StatusOK, StatusProxyAuthSupported:
		line += f.renderHTML(fmt.Sprintf(`<span class="success">%s</span>`, statusStr))
	case StatusReachable:
		line += f.renderHTML(fmt.Sprintf(`<span class="warning">%s</span>`, statusStr))
	default:
		message := statusStr
		if result.Error != nil {
			message = fmt.Sprintf("%s - %v", statusStr, result.Error)
		}
		line += f.renderHTML(fmt.Sprintf(`<span class="error">%s</span>`, message))
	}

	return f.ui.Output(line)
}

// formatTODOs formats the actionable TODO items
func (f *Formatter) formatTODOs(todos []TODO) error {
	f.output("")
	f.output(presenters.RenderTitle("Actionable TODOs"))

	if len(todos) == 0 {
		f.output(f.renderHTML(`<span class="success">All checks passed. Your network configuration appears to be compatible with Snyk CLI.</span>`))
		f.output("")
		tip := presenters.RenderTip("Certificate Configuration:\nIf you need to trust custom certificates, set NODE_EXTRA_CA_CERTS environment variable\nto point to your certificate bundle file.")
		f.output(tip)
		return nil
	}

	uniqueTodos := deduplicateTODOs(todos)

	for _, todo := range uniqueTodos {
		var htmlClass string
		switch todo.Level {
		case TodoFail:
			htmlClass = "error"
		case TodoWarn:
			htmlClass = "warning"
		case TodoInfo:
			htmlClass = "success"
		}

		message := fmt.Sprintf("%s: %s", todo.Level, todo.Message)
		f.output(f.renderHTML(fmt.Sprintf(`<span class="%s">%s</span>`, htmlClass, message)))
	}

	return nil
}

// formatOrganizations formats the organization list
func (f *Formatter) formatOrganizations(result *ConnectivityCheckResult) error {
	f.output("")
	f.output(presenters.RenderTitle("Snyk Token and Organizations"))

	if !result.TokenPresent {
		f.output(f.renderHTML(`<span class="warning">No authentication token configured</span>`))
		f.output("Configure authentication token to see your organizations")
		return nil
	}

	f.output(f.renderHTML(`<span class="success">✓ Authentication token is configured</span>`))

	if result.OrgCheckError != nil {
		errMsg := fmt.Sprintf(`<span class="error">✗</span> Failed to fetch organizations: %v`, result.OrgCheckError)
		f.output(f.renderHTML(errMsg))
		return result.OrgCheckError
	}

	if len(result.Organizations) == 0 {
		f.output(f.renderHTML(`<span class="warning">No organizations found</span>`))
		return nil
	}

	f.output("")
	f.output(f.renderHTML(fmt.Sprintf(`<span class="success">Found %d organizations:</span>`, len(result.Organizations))))
	f.output("")

	groupIdWidth, nameWidth, slugWidth, defaultWidth := 36, 20, 20, 7 // UUID length is 36, "Default" is 7
	for _, org := range result.Organizations {
		if len(org.GroupID) > groupIdWidth {
			groupIdWidth = len(org.GroupID)
		}
		if len(org.Name) > nameWidth {
			nameWidth = len(org.Name)
		}
		if len(org.Slug) > slugWidth {
			slugWidth = len(org.Slug)
		}
	}

	groupIdWidth += 2
	nameWidth += 2
	slugWidth += 2
	defaultWidth += 2

	header := fmt.Sprintf("%-*s %-*s %-*s %-*s", groupIdWidth, "Group ID", nameWidth, "Name", slugWidth, "Slug", defaultWidth, "Default")
	f.output(f.renderHTML(fmt.Sprintf(`<span class="info">%s</span>`, header)))
	f.output(f.renderHTML(fmt.Sprintf(`<span class="info">%s</span>`, strings.Repeat("-", len(header)))))

	for _, org := range result.Organizations {
		defaultStr := ""
		if org.IsDefault {
			defaultStr = "Yes"
		}

		orgLine := fmt.Sprintf("%-*s %-*s %-*s %-*s",
			groupIdWidth, org.GroupID,
			nameWidth, org.Name,
			slugWidth, org.Slug,
			defaultWidth, defaultStr)

		if org.IsDefault {
			f.output(f.renderHTML(fmt.Sprintf(`<span class="success">%s</span>`, orgLine)))
		} else {
			f.output(orgLine)
		}
	}

	return nil
}

// renderHTML converts HTML-like markup to ANSI colors using GAF's HTML presenter
func (f *Formatter) renderHTML(html string) string {
	if !f.useColor {
		// Strip HTML tags if color is disabled
		presenter := presenters.NewHTMLPresenter(func(tag, cssClass, originalContent string) string {
			return originalContent
		})
		output, err := presenter.Present(html)
		if err != nil {
			return html
		}
		return output
	}

	presenter := presenters.NewHTMLPresenter(func(tag, cssClass, originalContent string) string {
		switch cssClass {
		case "success":
			return lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render(originalContent)
		case "warning":
			return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(originalContent)
		case "error":
			return lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(originalContent)
		case "info":
			return lipgloss.NewStyle().Foreground(lipgloss.Color("4")).Render(originalContent)
		case "dim":
			return lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(originalContent)
		case "proxy-info":
			return lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Render(originalContent)
		case "url":
			return lipgloss.NewStyle().Underline(true).Render(originalContent)
		default:
			return originalContent
		}
	})

	output, err := presenter.Present(html)
	if err != nil {
		return html
	}
	return output
}

// getEnvOrEmpty returns the value of an environment variable or empty string
func getEnvOrEmpty(key string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return ""
}

// deduplicateTODOs removes duplicate TODO messages
func deduplicateTODOs(todos []TODO) []TODO {
	seen := make(map[string]bool)
	unique := []TODO{}

	for _, todo := range todos {
		key := fmt.Sprintf("%d:%s", todo.Level, todo.Message)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, todo)
		}
	}

	return unique
}
