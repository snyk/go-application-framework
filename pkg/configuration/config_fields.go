package configuration

// Annotation key constants for pflag.Flag.Annotations used by the flagset-native config system.
const (
	AnnotationScope       = "config.scope"
	AnnotationRemoteKey   = "config.remoteKey"
	AnnotationDisplayName = "config.displayName"
	AnnotationDescription = "config.description"
	AnnotationIdeKey      = "config.ideKey"
)

// RemoteConfigField holds a single configuration value received from remote config (e.g. LDX-Sync).
// IsLocked: admin prevents any override; LS rejects edit attempts.
type RemoteConfigField struct {
	Value    any
	IsLocked bool
	Origin   string
}

// LocalConfigField holds a single user-provided configuration value.
// Changed must be true for the resolver to treat this as an active override.
type LocalConfigField struct {
	Value   any
	Changed bool
}

// ConfigSource identifies which layer of the precedence chain resolved a value.
type ConfigSource int

const (
	ConfigSourceDefault        ConfigSource = iota // default value from flag registration
	ConfigSourceUserGlobal                         // user:global:<name>
	ConfigSourceUserOverride                       // user:folder:<folderPath>:<name> (org-scope override)
	ConfigSourceFolder                             // user:folder:<folderPath>:<name> (folder-scope)
	ConfigSourceRemote                             // remote:<orgId>:<name> — regular
	ConfigSourceRemoteLocked                       // remote:<orgId>:<name> — locked
)
