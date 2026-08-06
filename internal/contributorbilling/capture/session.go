package capture

import "sync"

// ConfigurationKeyCaptureEnabled gates contributor billing HTTP capture. Resolved via
// feature-flag-service (see FeatureFlagEnableEntityContributorsPublish in app setup).
const ConfigurationKeyCaptureEnabled = "contributor_billing_capture_enabled"

// FeatureFlagEnableEntityContributorsPublish is the FFS key shared with entitlements-service
// ingest (ReleaseFlagKeys.ENABLE_ENTITY_CONTRIBUTORS_PUBLISH / appsecex_admin).
const FeatureFlagEnableEntityContributorsPublish = "enable-entity-contributors-publish"

var commandSession session

type session struct {
	mu       sync.Mutex
	capture  *Capture
	repoPath string
}

// OpenCommandSession starts one command-scoped capture session.
func OpenCommandSession(repoPath string) *Capture {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	bag := NewCapture()
	commandSession.capture = bag
	commandSession.repoPath = repoPath
	return bag
}

// EnsureCommandSession opens a capture session when none is active and returns the active bag.
func EnsureCommandSession(repoPath string) *Capture {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	if commandSession.capture == nil {
		bag := NewCapture()
		commandSession.capture = bag
		commandSession.repoPath = repoPath
		return bag
	}
	return commandSession.capture
}

// CloseCommandSession ends the active session and returns its capture bag and repo path.
func CloseCommandSession() (*Capture, string) {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	bag := commandSession.capture
	repoPath := commandSession.repoPath
	commandSession.capture = nil
	commandSession.repoPath = ""
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
}
