package contributorbilling

import "time"

const (
	// SourceCLI is the ingest payload source value for CLI-originated billing events.
	SourceCLI = "cli"

	// CapabilityOSS is the ingest capability for open-source monitor flows.
	CapabilityOSS = "oss"
	// CapabilityCode is the ingest capability for Snyk Code report flows.
	CapabilityCode = "code"
	// CapabilityIaC is the ingest capability for IaC registry share flows.
	CapabilityIaC = "iac"

	// DefaultIngestPath is the proposed entitlements-service ingest path.
	// TODO: confirm against entitlements-service OpenAPI once Part 1 lands.
	DefaultIngestPath = "/rest/api/hidden/contributors/ingest"

	// DefaultTimeout bounds the fire-and-forget HTTP POST so callers are never blocked.
	DefaultTimeout = 5 * time.Second

	// ContributingDeveloperPeriodDays matches the CLI usage-path contributor window.
	ContributingDeveloperPeriodDays = 90

	// MaxCommitsInGitLog caps git log traversal to stay within practical payload limits.
	MaxCommitsInGitLog = 500
)
