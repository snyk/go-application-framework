package clibilling

import (
	"context"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ContributorBillingPostInvokeHook waits for contributor billing ingest started during capture.
func ContributorBillingPostInvokeHook(ctx context.Context, engine workflow.Engine, hctx workflow.PostInvokeContext) {
	config := engine.GetConfiguration()
	if config == nil || !captureEnabled(config) || !capture.IsBillableCommand(ActiveCommand(engine)) {
		return
	}
	if shouldSkipPostInvokeWait(hctx.GetWorkflowIdentifier()) {
		return
	}

	WaitForPendingEmit(ctx, engine, config)
}

func shouldSkipPostInvokeWait(id workflow.Identifier) bool {
	switch id.String() {
	case localworkflows.WORKFLOWID_FILTER_FINDINGS.String(),
		localworkflows.WORKFLOWID_OUTPUT_WORKFLOW.String(),
		localworkflows.WORKFLOWID_REPORT_ANALYTICS.String():
		return true
	default:
		return false
	}
}
