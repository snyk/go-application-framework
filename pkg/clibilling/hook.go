package clibilling

import (
	"context"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ContributorBillingPostInvokeHook discards capture state when a billable top-level workflow
// fails. Successful billable workflows keep the session open until FinishCommand runs at CLI
// teardown so downstream filter/output invocations and the final exit code gate still apply.
func ContributorBillingPostInvokeHook(ctx context.Context, engine workflow.Engine, hctx workflow.PostInvokeContext) {
	_ = ctx

	config := engine.GetConfiguration()
	if config == nil || !captureEnabled(config) || !capture.IsBillableCommand(ActiveCommand(engine)) {
		return
	}
	if shouldSkipPostInvokeFinalize(hctx.GetWorkflowIdentifier()) {
		return
	}
	if hctx.GetError() != nil {
		capture.CloseCommandSession()
	}
}

func shouldSkipPostInvokeFinalize(id workflow.Identifier) bool {
	switch id.String() {
	case localworkflows.WORKFLOWID_FILTER_FINDINGS.String(),
		localworkflows.WORKFLOWID_OUTPUT_WORKFLOW.String():
		return true
	default:
		return false
	}
}
