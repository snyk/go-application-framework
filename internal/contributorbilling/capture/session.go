package capture

import (
	"sync"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// ConfigurationKeyCaptureEnabled gates contributor billing HTTP capture. Resolved via
// feature-flag-service (see FeatureFlagEnableEntityContributorsPublish in app setup).
const ConfigurationKeyCaptureEnabled = "contributor_billing_capture_enabled"

// FeatureFlagEnableEntityContributorsPublish is the FFS key shared with entitlements-service
// ingest (ReleaseFlagKeys.ENABLE_ENTITY_CONTRIBUTORS_PUBLISH / appsecex_admin).
const FeatureFlagEnableEntityContributorsPublish = "enable-entity-contributors-publish"

// FirstRecordHandler runs after the first billable project ID is captured and the session is sealed.
type FirstRecordHandler func()

var commandSession session

type session struct {
	mu                 sync.Mutex
	capture            *Capture
	repoPath           string
	captureConfig      configuration.Configuration
	sealed             bool
	firstRecordHandler FirstRecordHandler
}

// RegisterFirstRecordHandler wires the callback invoked when the first billable entity is captured.
func RegisterFirstRecordHandler(handler FirstRecordHandler) {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()
	commandSession.firstRecordHandler = handler
}

// OpenCommandSession starts one command-scoped capture session.
func OpenCommandSession(repoPath string) *Capture {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	bag := NewCapture()
	commandSession.capture = bag
	commandSession.repoPath = repoPath
	commandSession.captureConfig = nil
	commandSession.sealed = false
	return bag
}

// EnsureCommandSession opens a capture session when none is active and returns the active bag.
func EnsureCommandSession(repoPath string) *Capture {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	if commandSession.sealed && commandSession.capture == nil {
		return nil
	}
	if commandSession.capture != nil {
		return commandSession.capture
	}

	bag := NewCapture()
	commandSession.capture = bag
	commandSession.repoPath = repoPath
	commandSession.captureConfig = nil
	return bag
}

// SessionConfiguration returns the configuration active when capture opened.
func SessionConfiguration() configuration.Configuration {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()
	return commandSession.captureConfig
}

// IsSessionSealed reports whether further capture is disabled for the active command session.
func IsSessionSealed() bool {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()
	return commandSession.sealed
}

// SessionRepoPath returns the repo path for the active command session.
func SessionRepoPath() string {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()
	return commandSession.repoPath
}

// SealAndNotifyFirstRecord seals the session after the first billable entity is captured and
// invokes the registered first-record handler, if any.
func SealAndNotifyFirstRecord() {
	commandSession.mu.Lock()
	if commandSession.sealed || commandSession.capture == nil || !commandSession.capture.HasRecords() {
		commandSession.mu.Unlock()
		return
	}

	commandSession.sealed = true
	handler := commandSession.firstRecordHandler
	commandSession.mu.Unlock()

	if handler != nil {
		handler()
	}
}

// CloseCommandSession ends the active session and returns its capture bag and repo path.
func CloseCommandSession() (*Capture, string) {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	bag := commandSession.capture
	repoPath := commandSession.repoPath
	commandSession.capture = nil
	commandSession.repoPath = ""
	commandSession.captureConfig = nil
	commandSession.sealed = false
	return bag, repoPath
}

// ActiveCapture returns the in-flight command capture bag, if any.
func ActiveCapture() *Capture {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()
	return commandSession.capture
}

// ResetCommandSession clears any active session. Used by tests and defensive teardown paths.
func ResetCommandSession() {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()
	commandSession.capture = nil
	commandSession.repoPath = ""
	commandSession.captureConfig = nil
	commandSession.sealed = false
}
