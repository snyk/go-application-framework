package configresolver

// Annotation key constants for pflag.Flag.Annotations used by the flagset-native config system.
const (
	AnnotationScope       = "config.scope"
	AnnotationRemoteKey   = "config.remoteKey"
	AnnotationDisplayName = "config.displayName"
	AnnotationDescription = "config.description"
	AnnotationIdeKey      = "config.ideKey"
	AnnotationWriteOnly   = "config.writeOnly"
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
// Wire protocol semantics (as *LocalConfigField):
//   - nil pointer = omitted (don't change)
//   - Changed: true + Value: non-nil = set override
//   - Changed: true + Value: nil = clear/reset to default
type LocalConfigField struct {
	Value   any  `json:"value"`
	Changed bool `json:"changed"`
}

// ConfigSource identifies which layer of the precedence chain resolved a value.
type ConfigSource int

const (
	ConfigSourceDefault            ConfigSource = iota // default value from flag registration
	ConfigSourceLocal                                  // set locally (env var, CLI flag, config file, or explicit Set)
	ConfigSourceUserGlobal                             // user:global:<name>
	ConfigSourceUserFolderOverride                     // user:folder:<folderPath>:<name> (org-scope override)
	ConfigSourceFolder                                 // user:folder:<folderPath>:<name> (folder-scope)
	ConfigSourceRemote                                 // remote:<orgId>:<name> — regular
	ConfigSourceRemoteLocked                           // remote:<orgId>:<name> — locked
)
