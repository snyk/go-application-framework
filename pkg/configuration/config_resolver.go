package configuration

// ConfigResolver is a stateless resolver that applies the precedence chain for each configuration
// scope (machine, org, folder). effectiveOrg and folderPath are parameters, never stored state.
//
// Precedence rules:
//   - Machine: locked remote > user global > enforced remote > remote > default
//   - Org:     locked remote > user folder override > enforced remote > user global > remote > default
//   - Folder:  folder value > default
type ConfigResolver struct {
	conf Configuration
}

// NewConfigResolver creates a ConfigResolver backed by the given Configuration instance.
// The Configuration must implement FlagMetadata (i.e. be created via New/NewInMemory/NewWithOpts
// and have had AddFlagSet called with annotated flags).
func NewConfigResolver(conf Configuration) *ConfigResolver {
	return &ConfigResolver{conf: conf}
}

// Resolve returns the effective value and its source for the named setting given an effective
// organization ID and folder path. Both effectiveOrg and folderPath are stateless parameters.
func (r *ConfigResolver) Resolve(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	fm, ok := r.conf.(FlagMetadata)
	if !ok {
		return r.conf.Get(name), ConfigSourceDefault
	}

	scope, _ := fm.GetFlagAnnotation(name, AnnotationScope)

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
func (r *ConfigResolver) ResolveBool(name, effectiveOrg, folderPath string) bool {
	val, _ := r.Resolve(name, effectiveOrg, folderPath)
	b, _ := val.(bool)
	return b
}

// IsLocked reports whether the setting is locked in the remote config for the given org.
func (r *ConfigResolver) IsLocked(name, effectiveOrg string) bool {
	f := r.remoteField(RemoteOrgKey(effectiveOrg, name))
	return f != nil && f.IsLocked
}

// IsEnforced reports whether the setting is enforced in the remote config for the given org.
func (r *ConfigResolver) IsEnforced(name, effectiveOrg string) bool {
	f := r.remoteField(RemoteOrgKey(effectiveOrg, name))
	return f != nil && f.IsEnforced
}

// isUserSet returns true only when the key is explicitly set to a real value (not the keyDeleted marker).
func (r *ConfigResolver) isUserSet(key string) bool {
	if !r.conf.IsSet(key) {
		return false
	}
	// keyDeleted is the internal marker used by Unset(); treat it as not set.
	return r.conf.Get(key) != keyDeleted
}

// resolveMachine applies: locked remote > user global > enforced remote > remote > default
func (r *ConfigResolver) resolveMachine(name, effectiveOrg string) (any, ConfigSource) {
	remote := r.remoteField(RemoteOrgKey(effectiveOrg, name))

	// 1. locked remote
	if remote != nil && remote.IsLocked {
		return remote.Value, ConfigSourceRemoteLocked
	}

	// 2. user global
	if r.isUserSet(UserGlobalKey(name)) {
		return r.conf.Get(UserGlobalKey(name)), ConfigSourceUserGlobal
	}

	// 3. enforced remote
	if remote != nil && remote.IsEnforced {
		return remote.Value, ConfigSourceRemoteEnforced
	}

	// 4. regular remote
	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	// 5. default
	return r.conf.Get(name), ConfigSourceDefault
}

// resolveOrg applies: locked remote > user folder override > enforced remote > user global > remote > default
func (r *ConfigResolver) resolveOrg(name, effectiveOrg, folderPath string) (any, ConfigSource) {
	remote := r.remoteField(RemoteOrgKey(effectiveOrg, name))

	// 1. locked remote
	if remote != nil && remote.IsLocked {
		return remote.Value, ConfigSourceRemoteLocked
	}

	// 2. user folder override (Changed must be true and key not deleted)
	if folderPath != "" {
		key := UserFolderKey(folderPath, name)
		if r.conf.IsSet(key) {
			if lf := r.localField(key); lf != nil && lf.Changed {
				return lf.Value, ConfigSourceUserOverride
			}
		}
	}

	// 3. enforced remote
	if remote != nil && remote.IsEnforced {
		return remote.Value, ConfigSourceRemoteEnforced
	}

	// 4. user global
	if r.isUserSet(UserGlobalKey(name)) {
		return r.conf.Get(UserGlobalKey(name)), ConfigSourceUserGlobal
	}

	// 5. regular remote
	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	// 6. default
	return r.conf.Get(name), ConfigSourceDefault
}

// resolveFolder applies: folder value > default
func (r *ConfigResolver) resolveFolder(name, folderPath string) (any, ConfigSource) {
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
func (r *ConfigResolver) remoteField(key string) *RemoteConfigField {
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
func (r *ConfigResolver) localField(key string) *LocalConfigField {
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
