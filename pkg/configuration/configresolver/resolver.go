package configresolver

import (
	"reflect"
	"strconv"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Resolver is a stateless resolver that applies the precedence chain for each configuration
// scope (machine, folder). effectiveOrg and folderPath are parameters, never stored state.
type Resolver struct {
	conf configuration.Configuration
	fm   workflow.ConfigurationOptionsMetaData
}

// New creates a Resolver backed by the given Configuration and ConfigurationOptionsMetaData.
func New(conf configuration.Configuration, fm workflow.ConfigurationOptionsMetaData) *Resolver {
	return &Resolver{conf: conf, fm: fm}
}

type Scope string

const MachineScope Scope = "machine"
const FolderScope Scope = "folder"

// Resolve returns the effective value and its source for the named setting given an effective
// organization ID and folder path. Both effectiveOrg and folderPath are stateless parameters.
//
// Precedence rules (org can have both machine and folder level settings):
//   - Machine: locked remote > user global > remote > default
//   - Folder:  locked remote > folder value > remote > user global > default
func (r *Resolver) Resolve(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	if r.fm == nil {
		return r.fallback(name)
	}

	scope, _ := r.fm.GetConfigurationOptionAnnotation(name, AnnotationScope)

	switch Scope(scope) {
	case MachineScope:
		return r.resolveMachine(name, effectiveOrg)
	case FolderScope:
		return r.resolveFolder(name, effectiveOrg, folderPath)
	default:
		return r.fallback(name)
	}
}

// ResolveBool is a typed convenience wrapper around Resolve.
// Handles native bool, string representations ("true", "1", etc.),
// and all Go numeric types (int*, uint*, float*) where non-zero means true.
func (r *Resolver) ResolveBool(name, effectiveOrg, folderPath string) bool {
	val, _ := r.Resolve(name, effectiveOrg, folderPath)
	return anyToBool(val)
}

func anyToBool(val any) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(v)
		return err == nil && b
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	default:
		rv := reflect.ValueOf(val)
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return rv.Int() != 0
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return rv.Uint() != 0
		case reflect.Float32, reflect.Float64:
			return rv.Float() != 0
		default:
			return false
		}
	}
}

// IsLocked reports whether the setting is locked in the remote config.
// For machine-scope flags, folderPath is ignored.
// The folderPath parameter is only used for folder level scope and thus optional.
func (r *Resolver) IsLocked(name, effectiveOrg string, folderPath ...string) bool {
	fp := ""
	if len(folderPath) > 0 {
		fp = folderPath[0]
	}

	if fp != "" && r.fm != nil {
		if scope, found := r.fm.GetConfigurationOptionAnnotation(name, AnnotationScope); found && scope != string(MachineScope) {
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
		if scope, found := r.fm.GetConfigurationOptionAnnotation(name, AnnotationScope); found && scope == string(MachineScope) {
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

	ugk := UserGlobalKey(name)
	if r.isUserSet(ugk) {
		if lf := r.localField(ugk); lf != nil {
			if lf.Changed {
				return lf.Value, ConfigSourceUserGlobal
			}
		} else {
			return r.conf.Get(ugk), ConfigSourceUserGlobal
		}
	}

	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	return r.fallback(name)
}

// with folder-level taking precedence over org-level.
// resolveFolder applies: locked remote > folder value > remote folder > user global > remote global > default
func (r *Resolver) resolveFolder(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	remoteFolder := r.remoteFolderField(effectiveOrg, folderPath, name)
	remoteOrg := r.remoteField(RemoteOrgKey(effectiveOrg, name))

	if remoteFolder != nil && remoteFolder.IsLocked {
		return remoteFolder.Value, ConfigSourceRemoteLocked
	}
	if remoteOrg != nil && remoteOrg.IsLocked {
		return remoteOrg.Value, ConfigSourceRemoteLocked
	}

	if folderPath != "" {
		ufk := UserFolderKey(folderPath, name)
		if r.conf.IsSet(ufk) {
			if lf := r.localField(ufk); lf != nil && lf.Changed {
				return lf.Value, ConfigSourceUserFolderOverride
			}
		}
	}

	if remoteFolder != nil {
		return remoteFolder.Value, ConfigSourceRemote
	}

	ugk := UserGlobalKey(name)
	if r.isUserSet(ugk) {
		if lf := r.localField(ugk); lf != nil {
			if lf.Changed {
				return lf.Value, ConfigSourceUserGlobal
			}
		} else {
			return r.conf.Get(ugk), ConfigSourceUserGlobal
		}
	}

	if remoteOrg != nil {
		return remoteOrg.Value, ConfigSourceRemote
	}

	return r.fallback(name)
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

// fallback returns the value from the underlying configuration for name along with the
// appropriate source: ConfigSourceLocal when the key is actively set (env var, CLI flag,
// config file, explicit Set), ConfigSourceDefault when it is truly a flag default.
func (r *Resolver) fallback(name string) (any, ConfigSource) {
	if r.conf.IsSet(name) {
		return r.conf.Get(name), ConfigSourceLocal
	}
	return r.conf.Get(name), ConfigSourceDefault
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
