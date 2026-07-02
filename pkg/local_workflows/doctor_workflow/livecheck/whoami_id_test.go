package livecheck_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck"
)

// TestWhoAmIWorkflowID_matchesCanonical guards the locally derived whoami
// identifier against drifting from the canonical localworkflows.WORKFLOWID_WHOAMI.
//
// livecheck cannot import localworkflows in non-test code (localworkflows ->
// doctor_workflow -> livecheck would cycle), so the identifier is derived from
// its name in auth.go and pinned here instead. This external test package can
// import localworkflows because nothing imports it back.
func TestWhoAmIWorkflowID_matchesCanonical(t *testing.T) {
	assert.Equal(t, localworkflows.WORKFLOWID_WHOAMI, livecheck.WhoAmIWorkflowID,
		"whoami identifier drifted from localworkflows.WORKFLOWID_WHOAMI")
}
