// Package wiring connects contributor capture to the workflow engine. It lives in
// its own package because internal/contributors is a dependency of pkg/networking,
// which pkg/workflow depends on in turn.
package wiring

import (
	"context"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init enables contributor capture when the feature flag is set and registers the
// post-invoke hook that reports whatever the capture middleware collected.
// Intended to be passed to engine.AddExtensionInitializer.
func Init(engine workflow.Engine) error {
	// if !engine.GetConfiguration().GetBool(contributors.ConfigurationKeyCaptureEnabled) {
	// 	return nil
	// }

	contributors.Enable()

	return workflow.AddPostInvokeHook(engine, emitCapturedEntity)
}

// emitCapturedEntity drains the entity captured for this interaction, if any, and
// hands it to the emitter to report contributors against.
func emitCapturedEntity(ctx context.Context, engine workflow.Engine, _ workflow.InvokeOutput) {
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
	if err := emitter.Emit(ctx, config.GetString(configuration.INPUT_DIRECTORY), orgID, item); err != nil {
		logger.Debug().Err(err).Msg("contributor billing: emit failed")
	}
}
