package configresolver

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Resolver is a stateless resolver that applies the precedence chain for each configuration
// scope (machine, org, folder). effectiveOrg and folderPath are parameters, never stored state.
//
// Precedence rules:
//   - Machine: locked remote > user global > remote > default
//   - Org:     locked remote > user folder override > user global > remote > default
//   - Folder:  folder value > default
type Resolver struct {
	conf configuration.Configuration
	fm   workflow.FlagMetadata
}

// New creates a Resolver backed by the given Configuration and FlagMetadata.
func New(conf configuration.Configuration, fm workflow.FlagMetadata) *Resolver {
	return &Resolver{conf: conf, fm: fm}
}

// Resolve returns the effective value and its source for the named setting given an effective
// organization ID and folder path. Both effectiveOrg and folderPath are stateless parameters.
func (r *Resolver) Resolve(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	if r.fm == nil {
		return r.conf.Get(name), ConfigSourceDefault
	}

	scope, _ := r.fm.GetFlagAnnotation(name, AnnotationScope)

	switch scope {
	case "machine":
		return r.resolveMachine(name, effectiveOrg)
	case "org":
		return r.resolveOrg(name, effectiveOrg, folderPath)
	case "folder":
		return r.resolveFolder(name, folderPath)
	default:
		return r.conf.Get(name), ConfigSourceDefault
	}
}

// ResolveBool is a typed convenience wrapper around Resolve.
func (r *Resolver) ResolveBool(name, effectiveOrg, folderPath string) bool {
	val, _ := r.Resolve(name, effectiveOrg, folderPath)
	b, ok := val.(bool)
	if !ok {
		return false
	}
	return b
}

// IsLocked reports whether the setting is locked in the remote config.
// For org-scope flags, pass the effective org ID. For machine-scope flags,
// pass any value — the lookup uses RemoteMachineKey when the scope annotation is "machine".
func (r *Resolver) IsLocked(name, effectiveOrg string) bool {
	f := r.remoteField(r.remoteKeyForName(name, effectiveOrg))
	return f != nil && f.IsLocked
}

// remoteKeyForName returns the correct remote config key for the named setting based on its scope annotation.
func (r *Resolver) remoteKeyForName(name, effectiveOrg string) string {
	if r.fm != nil {
		if scope, found := r.fm.GetFlagAnnotation(name, AnnotationScope); found && scope == "machine" {
			return RemoteMachineKey(name)
		}
	}
	return RemoteOrgKey(effectiveOrg, name)
}

// isUserSet returns true only when the key is explicitly set to a real value (not the keyDeleted marker).
func (r *Resolver) isUserSet(key string) bool {
	if !r.conf.IsSet(key) {
		return false
	}
	return !configuration.IsKeyDeleted(r.conf.Get(key))
}

// resolveMachine applies: locked remote > user global > remote > default
// Machine-scope remote config is stored under RemoteMachineKey (remote:machine:<name>), not per-org.
func (r *Resolver) resolveMachine(name, _ string) (any, ConfigSource) {
	remote := r.remoteField(RemoteMachineKey(name))

	if remote != nil && remote.IsLocked {
		return remote.Value, ConfigSourceRemoteLocked
	}

	if r.isUserSet(UserGlobalKey(name)) {
		return r.conf.Get(UserGlobalKey(name)), ConfigSourceUserGlobal
	}

	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	return r.conf.Get(name), ConfigSourceDefault
}

// resolveOrg applies: locked remote > user folder override > user global > remote > default
func (r *Resolver) resolveOrg(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	remote := r.remoteField(RemoteOrgKey(effectiveOrg, name))

	if remote != nil && remote.IsLocked {
		return remote.Value, ConfigSourceRemoteLocked
	}

	if folderPath != "" {
		key := UserFolderKey(folderPath, name)
		if r.conf.IsSet(key) {
			if lf := r.localField(key); lf != nil && lf.Changed {
				return lf.Value, ConfigSourceUserFolderOverride
			}
		}
	}

	if r.isUserSet(UserGlobalKey(name)) {
		return r.conf.Get(UserGlobalKey(name)), ConfigSourceUserGlobal
	}

	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	return r.conf.Get(name), ConfigSourceDefault
}

// resolveFolder applies: folder value > default
func (r *Resolver) resolveFolder(name, folderPath string) (any, ConfigSource) {
	if folderPath != "" {
		key := UserFolderKey(folderPath, name)
		if r.conf.IsSet(key) {
			if lf := r.localField(key); lf != nil && lf.Changed {
				return lf.Value, ConfigSourceFolder
			}
		}
	}

	return r.conf.Get(name), ConfigSourceDefault
}

// remoteField retrieves a *RemoteConfigField stored at key, or nil if not present/wrong type.
func (r *Resolver) remoteField(key string) *RemoteConfigField {
	v := r.conf.Get(key)
	if v == nil {
		return nil
	}

	f, ok := v.(*RemoteConfigField)
	if !ok {
		return nil
	}

	return f
}

// localField retrieves a *LocalConfigField stored at key, or nil if not present/wrong type.
func (r *Resolver) localField(key string) *LocalConfigField {
	v := r.conf.Get(key)
	if v == nil {
		return nil
	}

	f, ok := v.(*LocalConfigField)
	if !ok {
		return nil
	}

	return f
}
