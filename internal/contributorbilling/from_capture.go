package contributorbilling

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// FromCaptureOptions configures billing POSTs from middleware-captured CLI records.
type FromCaptureOptions struct {
	ScopeID       string
	RepoPath      string
	IngestURL     string
	Configuration configuration.Configuration
	Engine        workflow.Engine
	Emitter       *Emitter
	Logger        *zerolog.Logger
	Timeout       time.Duration
}

// EmitFromCaptureFirstRecord posts contributor billing for the first deduplicated entity
// captured during a CLI interaction. Fire-and-forget; callers must wait on the same Emitter.
func EmitFromCaptureFirstRecord(ctx context.Context, bag *capture.Capture, opts FromCaptureOptions) {
	if bag == nil {
		return
	}

	record, ok := bag.FirstDedupedRecord()
	if !ok {
		return
	}

	single := capture.NewCapture()
	single.Add(record)
	EmitFromCapture(ctx, single, opts)
}

// EmitFromCapture posts contributor billing for deduplicated entities captured during
// a CLI interaction. Fire-and-forget; callers must wait on the same Emitter before exit.
func EmitFromCapture(ctx context.Context, bag *capture.Capture, opts FromCaptureOptions) {
	if bag == nil {
		return
	}

	records := bag.DedupedRecords()
	if len(records) == 0 {
		return
	}

	emitter := opts.Emitter
	if emitter == nil {
		emitter = defaultEmitter
	}

	logger := opts.Logger
	if logger == nil {
		nop := zerolog.Nop()
		logger = &nop
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = "."
	}
	if abs, err := filepath.Abs(repoPath); err == nil {
		repoPath = abs
	}

	scopeID := strings.TrimSpace(opts.ScopeID)
	if scopeID == "" {
		return
	}

	for capability, capabilityRecords := range groupCaptureRecordsByCapability(records) {
		items := make([]BillingItem, 0, len(capabilityRecords))
		for _, record := range capabilityRecords {
			entityType := strings.TrimSpace(record.EntityType)
			if entityType == "" {
				entityType = EntityTypeProject
			}
			items = append(items, BillingItem{
				EntityID:   record.EntityID,
				EntityType: entityType,
			})
		}

		emitter.EmitContributorBilling(ctx, EmitOptions{
			Configuration:       opts.Configuration,
			Engine:              opts.Engine,
			IngestURL:           strings.TrimSpace(opts.IngestURL),
			ScopeID:             scopeID,
			Capability:          billingCapabilityFromCapture(capability),
			Items:               items,
			RepoPath:            repoPath,
			CollectContributors: true,
			Timeout:             timeout,
			Logger:              logger,
		})
	}
}

func billingCapabilityFromCapture(capability capture.Capability) string {
	switch capability {
	case capture.CapabilityOSS:
		return CapabilityOSS
	case capture.CapabilityIaC:
		return CapabilityIaC
	case capture.CapabilityCode:
		return CapabilityCode
	default:
		return string(capability)
	}
}

func groupCaptureRecordsByCapability(records []capture.Record) map[capture.Capability][]capture.Record {
	grouped := make(map[capture.Capability][]capture.Record)
	for _, record := range records {
		grouped[record.Capability] = append(grouped[record.Capability], record)
	}
	return grouped
}
