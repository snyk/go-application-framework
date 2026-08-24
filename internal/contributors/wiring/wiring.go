// Package wiring connects contributor capture to the workflow engine. It lives in
// its own package because internal/contributors is a dependency of pkg/networking,
// which pkg/workflow depends on in turn.
package wiring

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init enables contributor capture when the feature flag is set and registers the
// post-invoke hook that reports whatever the capture middleware collected.
// Intended to be passed to engine.AddExtensionInitializer.
func Init(engine workflow.Engine) error {
	if engine == nil || engine.GetConfiguration() == nil {
		return nil
	}
	if !engine.GetConfiguration().GetBool(contributors.ConfigurationKeyCaptureEnabled) {
		return nil
	}

	contributors.Enable()

	return workflow.AddPostInvokeHook(engine, emitCapturedEntity)
}

// emitCapturedEntity drains the entity captured for this interaction, if any, and
// hands it to the emitter to report contributors against.
func emitCapturedEntity(ctx context.Context, engine workflow.Engine, output workflow.InvokeOutput) {
	if shouldSkipEmit(output) {
		return
	}

	sink := contributors.GetSink()
	if sink == nil {
		return
	}

	interactionID, ok := ctx.Value(networking.InteractionIdKey).(string)
	if !ok || interactionID == "" {
		return
	}

	entityType, entityID, ok := sink.Get(interactionID)
	if !ok {
		return
	}

	config, logger := engine.GetConfiguration(), engine.GetLogger()
	if config == nil || logger == nil {
		return
	}

	orgID, err := uuid.Parse(config.GetString(configuration.ORGANIZATION))
	if err != nil {
		logger.Debug().Err(err).Msg("contributor billing: unusable org ID, not emitting")
		return
	}

	emitter, err := contributors.New(engine.GetNetworkAccess().GetHttpClient(), config, logger)
	if err != nil {
		logger.Debug().Err(err).Msg("contributor billing: could not create emitter")
		return
	}

	item := contributors.Item{EntityType: entityType, EntityID: entityID}
	waitForEmit(ctx, logger, func() error {
		return emitter.Emit(context.WithoutCancel(ctx), repoPathFromConfig(config), orgID, item)
	})
}

func shouldSkipEmit(output workflow.InvokeOutput) bool {
	if output == nil {
		return false
	}
	switch output.GetWorkflowIdentifier().String() {
	case localworkflows.WORKFLOWID_FILTER_FINDINGS.String(),
		localworkflows.WORKFLOWID_OUTPUT_WORKFLOW.String(),
		localworkflows.WORKFLOWID_REPORT_ANALYTICS.String():
		return true
	default:
		return false
	}
}

func repoPathFromConfig(config configuration.Configuration) string {
	if config == nil {
		return "."
	}
	dirs := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(dirs) > 0 {
		if path := strings.TrimSpace(dirs[0]); path != "" {
			return path
		}
	}
	return "."
}

// waitForEmit runs emit in the background and blocks until it finishes so ingest
// can complete before the CLI process exits. If the hook context is canceled
// first, it still waits for the emit result.
func waitForEmit(ctx context.Context, logger *zerolog.Logger, emit func() error) {
	done := make(chan error, 1)
	go func() {
		done <- emit()
	}()

	select {
	case err := <-done:
		logEmitError(logger, err)
	case <-ctx.Done():
		logEmitError(logger, <-done)
	}
}

func logEmitError(logger *zerolog.Logger, err error) {
	if err == nil || logger == nil {
		return
	}
	logger.Debug().Err(err).Msg("contributor billing: emit failed")
}
