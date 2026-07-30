package contributorbilling

import (
	entitlements_service "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service"
	"time"
)

const (
	// CapabilityOSS is the CLI product flow for open-source monitor billing emit.
	CapabilityOSS = "oss"
	// CapabilityCode is the CLI product flow for Snyk Code report billing emit.
	CapabilityCode = "code"
	// CapabilityIaC is the CLI product flow for IaC registry share billing emit.
	CapabilityIaC = "iac"

	// EntityTypeProject is the default ES ingest entity type for Registry project public IDs.
	EntityTypeProject = "project"
	// EntityTypeTarget is the ES ingest entity type when callers have an org target UUID.
	EntityTypeTarget = "target"
	// EntityTypeRevision is the ES ingest entity type for revision-scoped entities.
	EntityTypeRevision = "revision"

	// DefaultIngestAPIVersion matches entitlements-service Contributing Devs Ingest API version.
	DefaultIngestAPIVersion = entitlements_service.DefaultIngestAPIVersion

	// DefaultTimeout bounds the fire-and-forget HTTP POST so callers are never blocked.
	DefaultTimeout = 5 * time.Second

	// ContributingDeveloperPeriodDays matches the CLI usage-path contributor window.
	ContributingDeveloperPeriodDays = 90

	// MaxCommitsInGitLog caps git log traversal to stay within practical payload limits.
	MaxCommitsInGitLog = 500
)
