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

// GAFFormatter formats connectivity check results using GAF UI components
type GAFFormatter struct {
	ui       ui.UserInterface
	useColor bool
}

// NewGAFFormatter creates a new formatter using GAF UI interfaces
func NewGAFFormatter(ui ui.UserInterface, useColor bool) *GAFFormatter {
	if useColor {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	return &GAFFormatter{
		ui:       ui,
		useColor: useColor,
	}
}

// FormatResult formats the complete connectivity check result using GAF presenters
func (f *GAFFormatter) FormatResult(result *ConnectivityCheckResult) error {
	// Format proxy configuration
	if err := f.formatProxyConfig(result.ProxyConfig); err != nil {
		return err
	}

	// Add spacing
	f.ui.Output("")

	// Format connectivity results header
	f.ui.Output(f.renderHTML(`<h2 class="section-title">Testing connectivity to Snyk endpoints...</h2>`))
	f.ui.Output("")

	// Format table headers
	f.ui.Output(fmt.Sprintf("%-30s %s", "Host", "Result"))
	f.ui.Output(presenters.RenderDivider())

	// Format each host result
	for _, hostResult := range result.HostResults {
		if err := f.formatHostResult(hostResult); err != nil {
			return err
		}
	}

	// Format TODOs
	if err := f.formatTODOs(result.TODOs); err != nil {
		return err
	}

	// Format organizations if token is present
	if err := f.formatOrganizations(result); err != nil {
		return err
	}

	return nil
}

// formatProxyConfig formats proxy configuration information
func (f *GAFFormatter) formatProxyConfig(config ProxyConfig) error {
	f.ui.Output("Checking for proxy configuration...")
	f.ui.Output("")
	f.ui.Output("Environment variables:")

	// Show all proxy variables
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
			f.ui.Output(fmt.Sprintf("  %-12s %s", pv.name+":", f.renderHTML(fmt.Sprintf(`<span class="warning">%s</span>`, pv.value))))
		} else {
			f.ui.Output(fmt.Sprintf("  %-12s %s", pv.name+":", f.renderHTML(`<span class="prompt-help">(not set)</span>`)))
		}
	}

	f.ui.Output("")
	if config.Detected {
		f.ui.Output(f.renderHTML(fmt.Sprintf(`<span class="success">✓ Proxy detected</span> via <span class="warning">%s</span>: <span class="warning">%s</span>`,
			config.Variable, config.URL)))
		f.ui.Output("Testing connectivity through proxy...")
	} else {
		f.ui.Output(f.renderHTML(`<span class="info">ℹ No proxy detected</span> - Testing direct connection...`))
	}

	return nil
}

// formatHostResult formats a single host result
func (f *GAFFormatter) formatHostResult(result HostResult) error {
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
func (f *GAFFormatter) formatTODOs(todos []TODO) error {
	f.ui.Output("")
	f.ui.Output(presenters.RenderTitle("Actionable TODOs"))

	if len(todos) == 0 {
		f.ui.Output(f.renderHTML(`<span class="success">All checks passed. Your network configuration appears to be compatible with Snyk CLI.</span>`))
		f.ui.Output("")
		tip := presenters.RenderTip("Certificate Configuration:\nIf you need to trust custom certificates, set NODE_EXTRA_CA_CERTS environment variable\nto point to your certificate bundle file.")
		f.ui.Output(tip)
		return nil
	}

	// Group and deduplicate TODOs
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
		f.ui.Output(f.renderHTML(fmt.Sprintf(`<span class="%s">%s</span>`, htmlClass, message)))
	}

	return nil
}

// formatOrganizations formats the organization list
func (f *GAFFormatter) formatOrganizations(result *ConnectivityCheckResult) error {
	f.ui.Output("")
	f.ui.Output(presenters.RenderTitle("Snyk Token and Organizations"))

	if !result.TokenPresent {
		f.ui.Output(f.renderHTML(`<span class="warning">No authentication token configured</span>`))
		f.ui.Output("Configure authentication token to see your organizations")
		return nil
	}

	f.ui.Output(f.renderHTML(`<span class="success">✓ Authentication token is configured</span>`))

	if result.OrgCheckError != nil {
		errMsg := fmt.Sprintf(`<span class="error">✗</span> Failed to fetch organizations: %v`, result.OrgCheckError)
		f.ui.Output(f.renderHTML(errMsg))
		return nil
	}

	if len(result.Organizations) == 0 {
		f.ui.Output(f.renderHTML(`<span class="warning">No organizations found</span>`))
		return nil
	}

	f.ui.Output("")
	f.ui.Output(f.renderHTML(fmt.Sprintf(`<span class="success">Found %d organizations:</span>`, len(result.Organizations))))
	f.ui.Output("")

	// Calculate column widths
	idWidth, nameWidth, groupWidth := 36, 20, 20 // UUID length is 36
	for _, org := range result.Organizations {
		if len(org.ID) > idWidth {
			idWidth = len(org.ID)
		}
		if len(org.Name) > nameWidth {
			nameWidth = len(org.Name)
		}
		if len(org.Group.Name) > groupWidth {
			groupWidth = len(org.Group.Name)
		}
	}

	// Add padding
	idWidth += 2
	nameWidth += 2
	groupWidth += 2

	// Print header
	header := fmt.Sprintf("%-*s %-*s %-*s", idWidth, "Organization ID", nameWidth, "Organization Name", groupWidth, "Group")
	f.ui.Output(f.renderHTML(fmt.Sprintf(`<span class="info">%s</span>`, header)))
	f.ui.Output(f.renderHTML(fmt.Sprintf(`<span class="info">%s</span>`, strings.Repeat("-", len(header)))))

	// Print organizations
	for _, org := range result.Organizations {
		f.ui.Output(fmt.Sprintf("%-*s %-*s %-*s",
			idWidth, org.ID,
			nameWidth, org.Name,
			groupWidth, org.Group.Name))
	}

	return nil
}

// renderHTML converts HTML-like markup to ANSI colors using GAF's HTML presenter
func (f *GAFFormatter) renderHTML(html string) string {
	if !f.useColor {
		// Strip HTML tags if color is disabled
		presenter := presenters.NewHTMLPresenter(func(tag, cssClass, originalContent string) string {
			return originalContent
		})
		output, _ := presenter.Present(html)
		return output
	}

	// Use custom callback for our specific classes
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

	output, _ := presenter.Present(html)
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
