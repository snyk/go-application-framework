package configuration

// ConfigResolver is a stateless resolver that applies the precedence chain for each configuration
// scope (machine, org, folder). effectiveOrg and folderPath are parameters, never stored state.
//
// Precedence rules:
//   - Machine: locked remote > user global > remote > default
//   - Org:     locked remote > user folder override > user global > remote > default
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

// ResolveDefaultFunc returns a DefaultValueFunction that uses Configuration.Resolve to
// look up settingName through the full precedence chain (remote-locked → user-global →
// remote → folder → default).
//
// Recursion safety: if Resolve returns ConfigSourceDefault (i.e. it fell through to the
// bare key), the function returns existingValue unchanged so that the caller's own default
// applies — this prevents infinite recursion when the function is registered as the default
// for the same key via AddDefaultValue.
//
// Typical usage:
//
//	config.AddDefaultValue("snyk_code_enabled", configuration.ResolveDefaultFunc("snyk_code_enabled"))
func ResolveDefaultFunc(settingName string) DefaultValueFunction {
	return func(c Configuration, existingValue interface{}) (interface{}, error) {
		val, src, err := c.Resolve(settingName)
		if err != nil {
			return nil, err
		}

		// When the resolver fell through to the bare key (ConfigSourceDefault) it found
		// nothing in any prefixed key. Return existingValue so the caller's own default
		// applies. This also breaks any recursive call that reaches here via the
		// ConfigResolver's final Get(name) fallback (the recursion guard in Resolve
		// catches re-entrant calls before they reach this function, so src will be
		// ConfigSourceDefault in that case).
		if src == ConfigSourceDefault {
			return existingValue, nil
		}

		return val, nil
	}
}

// ResolveBool is a typed convenience wrapper around Resolve.
func (r *ConfigResolver) ResolveBool(name, effectiveOrg, folderPath string) bool {
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
func (r *ConfigResolver) IsLocked(name, effectiveOrg string) bool {
	f := r.remoteField(r.remoteKeyForName(name, effectiveOrg))
	return f != nil && f.IsLocked
}

// remoteKeyForName returns the correct remote config key for the named setting based on its scope annotation.
func (r *ConfigResolver) remoteKeyForName(name, effectiveOrg string) string {
	if fm, ok := r.conf.(FlagMetadata); ok {
		if scope, found := fm.GetFlagAnnotation(name, AnnotationScope); found && scope == "machine" {
			return RemoteMachineKey(name)
		}
	}
	return RemoteOrgKey(effectiveOrg, name)
}

// isUserSet returns true only when the key is explicitly set to a real value (not the keyDeleted marker).
func (r *ConfigResolver) isUserSet(key string) bool {
	if !r.conf.IsSet(key) {
		return false
	}
	// keyDeleted is the internal marker used by Unset(); treat it as not set.
	return r.conf.Get(key) != keyDeleted
}

// resolveMachine applies: locked remote > user global > remote > default
// Machine-scope remote config is stored under RemoteMachineKey (remote:machine:<name>), not per-org.
func (r *ConfigResolver) resolveMachine(name, _ string) (any, ConfigSource) {
	remote := r.remoteField(RemoteMachineKey(name))

	// 1. locked remote
	if remote != nil && remote.IsLocked {
		return remote.Value, ConfigSourceRemoteLocked
	}

	// 2. user global
	if r.isUserSet(UserGlobalKey(name)) {
		return r.conf.Get(UserGlobalKey(name)), ConfigSourceUserGlobal
	}

	// 3. regular remote
	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	// 4. default
	return r.conf.Get(name), ConfigSourceDefault
}

// resolveOrg applies: locked remote > user folder override > user global > remote > default
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

	// 3. user global
	if r.isUserSet(UserGlobalKey(name)) {
		return r.conf.Get(UserGlobalKey(name)), ConfigSourceUserGlobal
	}

	// 4. regular remote
	if remote != nil {
		return remote.Value, ConfigSourceRemote
	}

	// 5. default
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
