package connectivity

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[0;90m"
)

// Formatter formats connectivity check results for display
type Formatter struct {
	useColor bool
	writer   io.Writer
}

// NewFormatter creates a new result formatter
func NewFormatter(writer io.Writer, useColor bool) *Formatter {
	return &Formatter{
		writer:   writer,
		useColor: useColor,
	}
}

// FormatResult formats the complete connectivity check result
func (f *Formatter) FormatResult(result *ConnectivityCheckResult) error {
	// Format proxy configuration
	if err := f.formatProxyConfig(result.ProxyConfig); err != nil {
		return err
	}

	// Add some spacing
	fmt.Fprintln(f.writer)

	// Format connectivity results header
	fmt.Fprintln(f.writer, f.colorize(ColorBlue, "Testing connectivity to Snyk endpoints..."))
	fmt.Fprintln(f.writer)

	// Add table headers
	fmt.Fprintf(f.writer, "%-30s %s\n", "Host", "Result")
	fmt.Fprintf(f.writer, "%s\n", strings.Repeat("-", 70))

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
func (f *Formatter) formatProxyConfig(config ProxyConfig) error {
	fmt.Fprintln(f.writer, "Checking for proxy configuration...")
	fmt.Fprintln(f.writer)
	fmt.Fprintln(f.writer, "Environment variables:")

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
			fmt.Fprintf(f.writer, "  %-12s %s\n", pv.name+":", f.colorize(ColorYellow, pv.value))
		} else {
			fmt.Fprintf(f.writer, "  %-12s %s\n", pv.name+":", f.colorize(ColorGray, "(not set)"))
		}
	}

	fmt.Fprintln(f.writer)
	if config.Detected {
		fmt.Fprintf(f.writer, "%s via %s: %s\n",
			f.colorize(ColorGreen, "✓ Proxy detected"),
			f.colorize(ColorYellow, config.Variable),
			f.colorize(ColorYellow, config.URL))
		fmt.Fprintln(f.writer, "Testing connectivity through proxy...")
	} else {
		fmt.Fprintf(f.writer, "%s - Testing direct connection...\n",
			f.colorize(ColorBlue, "ℹ No proxy detected"))
	}

	return nil
}

// formatHostResult formats a single host result
func (f *Formatter) formatHostResult(result HostResult) error {
	fmt.Fprintf(f.writer, "%-30s ", result.DisplayHost)

	statusStr := result.Status.String()
	if result.StatusCode > 0 {
		statusStr = fmt.Sprintf("%s (HTTP %d)", statusStr, result.StatusCode)
	}

	// Color based on status
	switch result.Status {
	case StatusOK, StatusProxyAuthSupported:
		fmt.Fprintln(f.writer, f.colorize(ColorGreen, statusStr))
	case StatusReachable:
		fmt.Fprintln(f.writer, f.colorize(ColorYellow, statusStr))
	default:
		message := statusStr
		if result.Error != nil {
			message = fmt.Sprintf("%s - %v", statusStr, result.Error)
		}
		fmt.Fprintln(f.writer, f.colorize(ColorRed, message))
	}

	return nil
}

// formatTODOs formats the actionable TODO items
func (f *Formatter) formatTODOs(todos []TODO) error {
	fmt.Fprintln(f.writer)
	fmt.Fprintln(f.writer, f.colorize(ColorBlue, "--- Actionable TODOs ---"))

	if len(todos) == 0 {
		fmt.Fprintln(f.writer, f.colorize(ColorGreen, "All checks passed. Your network configuration appears to be compatible with Snyk CLI."))
		fmt.Fprintln(f.writer)
		fmt.Fprintln(f.writer, f.colorize(ColorBlue, "ℹ Certificate Configuration:"))
		fmt.Fprintln(f.writer, "If you need to trust custom certificates, set NODE_EXTRA_CA_CERTS environment variable")
		fmt.Fprintln(f.writer, "to point to your certificate bundle file.")
		return nil
	}

	// Group and deduplicate TODOs
	uniqueTodos := deduplicateTODOs(todos)

	for _, todo := range uniqueTodos {
		prefix := fmt.Sprintf("%s: ", todo.Level)
		message := prefix + todo.Message

		switch todo.Level {
		case TodoFail:
			fmt.Fprintln(f.writer, f.colorize(ColorRed, message))
		case TodoWarn:
			fmt.Fprintln(f.writer, f.colorize(ColorYellow, message))
		case TodoInfo:
			fmt.Fprintln(f.writer, f.colorize(ColorGreen, message))
		}
	}

	return nil
}

// formatOrganizations formats the organization list as a table
func (f *Formatter) formatOrganizations(result *ConnectivityCheckResult) error {
	fmt.Fprintln(f.writer)
	fmt.Fprintln(f.writer, f.colorize(ColorBlue, "--- Snyk Token and Organizations ---"))

	if !result.TokenPresent {
		fmt.Fprintln(f.writer, f.colorize(ColorYellow, "No authentication token configured"))
		fmt.Fprintln(f.writer, "Configure authentication token to see your organizations")
		return nil
	}

	fmt.Fprintln(f.writer, f.colorize(ColorGreen, "✓ Authentication token is configured"))

	if result.OrgCheckError != nil {
		fmt.Fprintf(f.writer, "%s Failed to fetch organizations: %v\n",
			f.colorize(ColorRed, "✗"), result.OrgCheckError)
		return nil //nolint:nilerr // We're handling the error by displaying it
	}

	if len(result.Organizations) == 0 {
		fmt.Fprintln(f.writer, f.colorize(ColorYellow, "No organizations found"))
		return nil
	}

	fmt.Fprintln(f.writer)
	fmt.Fprintln(f.writer, f.colorize(ColorGreen, fmt.Sprintf("Found %d organizations:", len(result.Organizations))))
	fmt.Fprintln(f.writer)

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
	fmt.Fprintln(f.writer, f.colorize(ColorCyan, header))
	fmt.Fprintln(f.writer, f.colorize(ColorCyan, strings.Repeat("-", len(header))))

	// Print organizations
	for _, org := range result.Organizations {
		fmt.Fprintf(f.writer, "%-*s %-*s %-*s\n",
			idWidth, org.ID,
			nameWidth, org.Name,
			groupWidth, org.Group.Name)
	}

	return nil
}

// colorize applies color codes to text if color is enabled
func (f *Formatter) colorize(color, text string) string {
	if !f.useColor {
		return text
	}
	return color + text + ColorReset
}

// getEnvOrEmpty returns environment variable value or empty string
func getEnvOrEmpty(key string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
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
