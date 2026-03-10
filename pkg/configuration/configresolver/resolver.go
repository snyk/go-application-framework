package configresolver

import (
	"strconv"

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
// Handles both native bool and string representations ("true", "1", etc.).
func (r *Resolver) ResolveBool(name, effectiveOrg, folderPath string) bool {
	val, _ := r.Resolve(name, effectiveOrg, folderPath)
	switch v := val.(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false
		}
		return b
	default:
		return false
	}
}

// IsLocked reports whether the setting is locked in the remote config.
// For org-scope flags it checks both folder-level and org-level remote keys.
// For machine-scope flags, folderPath is ignored.
func (r *Resolver) IsLocked(name, effectiveOrg string, folderPath ...string) bool {
	fp := ""
	if len(folderPath) > 0 {
		fp = folderPath[0]
	}

	if fp != "" && r.fm != nil {
		if scope, found := r.fm.GetFlagAnnotation(name, AnnotationScope); found && scope != "machine" {
			if f := r.remoteField(RemoteOrgFolderKey(effectiveOrg, fp, name)); f != nil && f.IsLocked {
				return true
			}
		}
	}

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
// Remote config is checked at both folder-level (RemoteOrgFolderKey) and org-level (RemoteOrgKey),
// with folder-level taking precedence over org-level.
func (r *Resolver) resolveOrg(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	remoteFolder := r.remoteFolderField(effectiveOrg, folderPath, name)
	remoteOrg := r.remoteField(RemoteOrgKey(effectiveOrg, name))

	if remoteFolder != nil && remoteFolder.IsLocked {
		return remoteFolder.Value, ConfigSourceRemoteLocked
	}
	if remoteOrg != nil && remoteOrg.IsLocked {
		return remoteOrg.Value, ConfigSourceRemoteLocked
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

	if remoteFolder != nil {
		return remoteFolder.Value, ConfigSourceRemote
	}
	if remoteOrg != nil {
		return remoteOrg.Value, ConfigSourceRemote
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

// remoteFolderField retrieves a *RemoteConfigField from the folder-level remote key, or nil.
func (r *Resolver) remoteFolderField(effectiveOrg, folderPath, name string) *RemoteConfigField {
	if folderPath == "" {
		return nil
	}
	return r.remoteField(RemoteOrgFolderKey(effectiveOrg, folderPath, name))
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
