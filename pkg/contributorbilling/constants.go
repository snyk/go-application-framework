package contributorbilling

import (
	entitlements_service "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service"
	"time"
)

const (
	// SourceCLI is the ingest payload source value for CLI-originated billing events.
	SourceCLI = "cli"

	// CapabilityOSS is the ingest capability for open-source monitor flows.
	CapabilityOSS = "oss"
	// CapabilityCode is the ingest capability for Snyk Code report flows.
	CapabilityCode = "code"
	// CapabilityIaC is the ingest capability for IaC registry share flows.
	CapabilityIaC = "iac"

	// DefaultIngestPath is the draft entitlements-service ingest path from the OpenAPI spec.
	DefaultIngestPath = entitlements_service.IngestPath

	// DefaultTimeout bounds the fire-and-forget HTTP POST so callers are never blocked.
	DefaultTimeout = 5 * time.Second

	// ContributingDeveloperPeriodDays matches the CLI usage-path contributor window.
	ContributingDeveloperPeriodDays = 90

	// MaxCommitsInGitLog caps git log traversal to stay within practical payload limits.
	MaxCommitsInGitLog = 500
)
