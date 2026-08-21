package contributors

// FeatureFlagEnableEntityContributorsPublish is the feature flag name for publishing
// contributor data.
const FeatureFlagEnableEntityContributorsPublish = "enable-entity-contributors-publish"

// ConfigurationKeyCaptureEnabled gates contributor billing HTTP capture. Resolved via
// feature-flag-service (see FeatureFlagEnableEntityContributorsPublish in app setup).
const ConfigurationKeyCaptureEnabled = "contributor_billing_capture_enabled"
