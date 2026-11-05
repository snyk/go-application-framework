package mocks

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var _ configuration.Configuration = (*MockConfiguration)(nil)
var _ auth.Authenticator = (*MockAuthenticator)(nil)
var _ auth.BearerTokenScoper = (*MockBearerTokenScoper)(nil)
var _ configuration.Storage = (*MockStorage)(nil)
var _ networking.NetworkAccess = (*MockNetworkAccess)(nil)
var _ ui.ProgressBar = (*MockProgressBar)(nil)
var _ runtimeinfo.RuntimeInfo = (*MockRuntimeInfo)(nil)
var _ ui.UserInterface = (*MockUserInterface)(nil)
var _ workflow.Data = (*MockData)(nil)
var _ workflow.Engine = (*MockEngine)(nil)
var _ workflow.Entry = (*MockEntry)(nil)
var _ workflow.InvocationContext = (*MockInvocationContext)(nil)

// Entries carry metadata only through workflow.EntryWithMetadata. A generated MockEntry must not implement it, so
// callers that type-assert for metadata see a plain entry.
func Test_MockEntry_DoesNotImplementEntryWithMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	var entry workflow.Entry = NewMockEntry(ctrl)

	_, ok := entry.(workflow.EntryWithMetadata)
	assert.False(t, ok)
}
