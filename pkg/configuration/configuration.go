package configuration

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

//go:generate go tool github.com/golang/mock/mockgen -source=configuration.go -destination ../mocks/configuration.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/

type DefaultValueFunction func(config Configuration, existingValue interface{}) (interface{}, error)

type configType string
type KeyType int

const NoCacheExpiration time.Duration = -1
const defaultCacheCleanupInterval = 1 * time.Minute
const inMemory configType = "in-memory"
const jsonFile configType = "json"
const (
	EnvVarKeyType      KeyType = iota
	UnspecifiedKeyType KeyType = iota
)

// Configuration is an interface for managing configuration values.
type Configuration interface {
	Clone() Configuration

	Set(key string, value interface{})
	Get(key string) interface{}
	Unset(key string)
	IsSet(key string) bool
	GetString(key string) string
	GetStringWithError(key string) (string, error)
	GetStringSlice(key string) []string
	GetBool(key string) bool
	GetBoolWithError(key string) (bool, error)
	GetDuration(key string) time.Duration
	GetDurationWithError(key string) (time.Duration, error)
	GetInt(key string) int
	GetFloat64(key string) float64
	GetUrl(key string) *url.URL
	GetWithError(key string) (interface{}, error)

	AddFlagSet(flagset *pflag.FlagSet) error
	AllKeys() []string
	AddDefaultValue(key string, defaultValue DefaultValueFunction)
	AddAlternativeKeys(key string, altKeys []string)
	GetAlternativeKeys(key string) []string
	GetAllKeysThatContainValues(key string) []string
	GetKeyType(key string) KeyType

	// AddKeyDependency can be used to describe that a certain key and its values actually depend on another value, this can then be used to clear the cache of a key when a depending key changes.
	// In words: key depends on dependencyKey.
	AddKeyDependency(key string, dependencyKey string) error

	// PersistInStorage ensures that when Set is called with the given key, it will be persisted in the config file.
	PersistInStorage(key string)
	SetStorage(storage Storage)
	GetStorage() Storage

	AutomaticEnv()
	GetAutomaticEnv() bool
	SetSupportedEnvVars(envVars ...string)
	GetSupportedEnvVars() []string
	SetSupportedEnvVarPrefixes(prefixes ...string)
	GetSupportedEnvVarPrefixes() []string
	SetFiles(files ...string)
	GetFiles() []string
	ReloadConfig() error
	ClearCache()
}

// extendedViper is a wrapper around the viper library.
// It adds support for default values and alternative keys.
type extendedViper struct {
	viper               *viper.Viper
	alternativeKeys     map[string][]string
	defaultValues       map[string]DefaultValueFunction
	configType          configType
	flagsets            []*pflag.FlagSet
	storage             Storage
	mutex               sync.RWMutex
	automaticEnvEnabled bool
	configFiles         []string
	defaultCache        *cache.Cache

	// pinnedFile is the file given to WithPinnedFile. When it is set, configFiles are not used.
	pinnedFile string

	// persistedKeys stores the keys that need to be persisted to storage when Set is called.
	// Only specific keys are persisted, so viper's native functionality is not used.
	persistedKeys map[string]bool

	// supportedEnvVarPrefixes store the namespace prefixes that should be supported.
	// Any env var without these prefixes, will be ignored by the configuration.
	supportedEnvVarPrefixes []string

	// supportedEnvVars store the env vars that should be supported REGARDLESS of its prefix. e.g. NODE_EXTRA_CA_CERTS
	supportedEnvVars []string

	interkeyDependencies map[string][]string
}

// StandardDefaultValueFunction is a default value function that returns the default value if the existing value is nil.
func StandardDefaultValueFunction(defaultValue interface{}) DefaultValueFunction {
	return func(_ Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue != nil {
			return existingValue, nil
		} else {
			return defaultValue, nil
		}
	}
}

// ImmutableDefaultValueFunction returns a default value function that always returns the same value.
func ImmutableDefaultValueFunction(defaultValue interface{}) DefaultValueFunction {
	return func(_ Configuration, _ interface{}) (interface{}, error) {
		return defaultValue, nil
	}
}

// determineBasePath returns the base path for the configuration files.
func determineBasePath() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}

	result := filepath.Join(homedir, ".config", "configstore")
	return result
}

// DefaultStorageDir returns the directory that holds the default configuration file.
func DefaultStorageDir() string {
	return determineBasePath()
}

// CreateConfigurationFile creates a configuration file with the given name.
func CreateConfigurationFile(filename string) (string, error) {
	configPath := determineBasePath()
	p := filepath.Join(configPath, filename)

	folder := filepath.Dir(p)
	err := os.MkdirAll(folder, 0755)
	if err != nil {
		return "", err
	}

	// create empty file
	err = os.WriteFile(p, []byte{}, 0755)
	if err != nil {
		return "", err
	}

	return p, err
}

type Opts = func(config Configuration)

func WithAutomaticEnv() Opts {
	return func(c Configuration) {
		c.AutomaticEnv()
	}
}

func WithSupportedEnvVars(envVars ...string) Opts {
	return func(c Configuration) {
		c.SetSupportedEnvVars(envVars...)
	}
}

func WithSupportedEnvVarPrefixes(prefixes ...string) Opts {
	return func(c Configuration) {
		c.SetSupportedEnvVarPrefixes(prefixes...)
	}
}

func WithFiles(files ...string) Opts {
	return func(c Configuration) {
		c.SetFiles(files...)
	}
}

// WithPinnedFile pins the configuration to one absolute file. The file is read and written as JSON, and it is also the
// storage, whose lock file sits next to it. A missing file is created by the first persisted write, and an empty or blank
// file is an empty configuration. Unlike WithFiles, nothing is searched, and a problem is reported: NewWithOpts logs it
// and gives an in-memory configuration without storage, Derive returns it. A corrupt or unreadable file is never
// overwritten. The path is cleaned lexically but not checked for trust, so it must not come from user input such as an
// IDE setting or a request parameter. When WithPinnedFile is given, WithFiles is ignored.
func WithPinnedFile(path string) Opts {
	return func(c Configuration) {
		ev, ok := c.(*extendedViper)
		if !ok {
			panic("configuration must be used with WithPinnedFile()")
		}
		ev.pinnedFile = path
	}
}

// WithCachingEnabled can be used to enable TTL based caching. Use NoCacheExpiration to keep values cached indefinitely.
func WithCachingEnabled(cacheDuration time.Duration) Opts {
	return func(c Configuration) {
		ev, ok := c.(*extendedViper)
		if !ok {
			panic("configuration must be used with WithCachingEnabled()")
		}

		localCache := cache.New(cacheDuration, defaultCacheCleanupInterval)
		ev.setCache(localCache)
		ev.viper.SetDefault(CONFIG_CACHE_DISABLED, false)
		ev.viper.SetDefault(CONFIG_CACHE_TTL, cacheDuration)
	}
}

// NewWithOpts creates a new snyk configuration file with optional parameters
func NewWithOpts(opts ...Opts) Configuration {
	config, err := createViperDefaultConfig(opts...)
	if err != nil {
		log.Printf("configuration: continuing in memory, %v", err)
	}
	return config
}

// New creates a new snyk configuration file.
func New() Configuration {
	config := NewWithOpts(
		WithFiles("snyk"),
		WithAutomaticEnv(),
	)
	return config
}

// Deprecated: Use NewWithOpts with configuration.WithFiles() and configuration.WithAutomaticEnv() options instead
//
// NewFromFiles creates a new Configuration instance from the given files.
func NewFromFiles(files ...string) Configuration {
	config := NewWithOpts(
		WithFiles(files...),
		WithAutomaticEnv(),
	)
	return config
}

func (ev *extendedViper) getConfigType() configType {
	return ev.configType
}

// Deprecated: Use NewWithOpts with configuration.WithAutomaticEnv() option instead
//
// NewInMemory creates a new Configuration instance that is not persisted to disk.
func NewInMemory() Configuration {
	config := NewWithOpts(
		WithAutomaticEnv(),
	)
	return config
}

// newExtendedViper creates a configuration without options, files or values.
func newExtendedViper() *extendedViper {
	config := &extendedViper{
		viper:                viper.New(),
		alternativeKeys:      make(map[string][]string),
		defaultValues:        make(map[string]DefaultValueFunction),
		persistedKeys:        make(map[string]bool),
		interkeyDependencies: make(map[string][]string),
	}
	config.viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	return config
}

// createViperDefaultConfig applies opts and reads the files. A problem with the pinned file is returned, and the
// configuration is then in memory.
func createViperDefaultConfig(opts ...Opts) (*extendedViper, error) {
	config := newExtendedViper()
	for _, opt := range opts {
		opt(config)
	}
	return config, config.loadFiles()
}

// loadFiles reads the pinned file, or else the files of WithFiles as before.
func (ev *extendedViper) loadFiles() error {
	if ev.pinnedFile != "" {
		ev.configFiles = nil
		return ev.pinFile()
	}
	if len(ev.configFiles) > 0 {
		ev.configType = jsonFile
		readConfigFilesIntoViper(ev.configFiles, ev)
	} else {
		ev.configType = inMemory
	}
	return nil
}

// pinFile reads the file of WithPinnedFile. A missing file is an empty configuration. Any other problem turns ev into an
// in-memory configuration without storage and is returned.
func (ev *extendedViper) pinFile() error {
	if err := validatePinnedFile(ev.pinnedFile); err != nil {
		ev.useMemory()
		return err
	}

	path := filepath.Clean(ev.pinnedFile)
	ev.storage = NewJsonStorage(path, WithConfiguration(ev), withBlankFileAsEmpty(), withExactNumbers())
	ev.configType = jsonFile
	ev.viper.SetConfigFile(path)
	ev.viper.SetConfigType("json")

	if content, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	err := ev.viper.ReadInConfig()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		ev.useMemory()
		return fmt.Errorf("configuration file %s is not used: %w", path, err)
	}
	return nil
}

// useMemory turns ev into an in-memory configuration without files or storage.
func (ev *extendedViper) useMemory() {
	ev.configFiles = nil
	ev.configType = inMemory
	ev.storage = nil
}

// validatePinnedFile rejects a path that cannot name a configuration file: not absolute, a NUL byte, a trailing separator,
// or an existing entry that is not a regular file, such as a directory or a named pipe.
func validatePinnedFile(path string) error {
	switch {
	case !filepath.IsAbs(path):
		return fmt.Errorf("configuration file %q is not an absolute path", path)
	case strings.ContainsRune(path, 0):
		return errors.New("configuration file path contains a NUL byte")
	case strings.HasSuffix(path, "/") || strings.HasSuffix(path, string(filepath.Separator)):
		return fmt.Errorf("configuration file path %q ends with a separator", path)
	}
	info, err := os.Stat(path)
	switch {
	case err == nil && info.IsDir():
		return fmt.Errorf("configuration file path %q is a directory", path)
	case err == nil && !info.Mode().IsRegular():
		// a named pipe or a device such as CON on Windows would block the read
		return fmt.Errorf("configuration file path %q is not a regular file", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		// nothing is read from a path that cannot be checked
		return fmt.Errorf("configuration file path %q cannot be checked: %w", path, err)
	}
	return nil
}

func readConfigFilesIntoViper(files []string, config *extendedViper) {
	configPath := determineBasePath()
	config.storage = config.createFileStorage(configPath)

	// prepare config files
	for _, file := range files {
		config.viper.SetConfigName(file)
	}

	config.viper.AddConfigPath(configPath)
	config.viper.AddConfigPath(".")

	// read config files
	//nolint:errcheck // breaking api change needed to fix this
	_ = config.viper.ReadInConfig()
}

// Derive returns a configuration with the registrations of base, but none of its values, cache contents or storage.
// base must be a configuration created by this package, such as one from NewWithOpts or Clone, because the registrations
// are read from its internal state. Any other implementation, including a wrapper that embeds a Configuration, gives an
// error, and no file is read.
//
// The result copies the default value functions (shared by reference), alternative keys, key dependencies, persisted
// keys, flag sets and supported environment variables and prefixes of base, and its automatic environment. Options in opts
// apply first, so a registration in opts wins over the one of base for the same key. Values set on base, such as an
// explicit MACHINE_ID, are not visible; Set what is needed.
//
// Persisted keys are copied, so a Set of one of them writes to the storage of the result. Without a storage, for example
// without WithPinnedFile, Set changes memory only; check GetStorage() != nil.
//
// A cache enabled on base is enabled on the result, with the TTL of base, unless opts enable a cache. Values are not
// carried over, so a cache that base has turned off with its CONFIG_CACHE_DISABLED value is enabled on the result.
//
// WithFiles works as in NewWithOpts. WithPinnedFile makes Derive return an error for a file that cannot be used.
func Derive(base Configuration, opts ...Opts) (Configuration, error) {
	src, ok := base.(*extendedViper)
	if !ok {
		return nil, fmt.Errorf("cannot derive from configuration of type %T", base)
	}

	derived := newExtendedViper()
	for _, opt := range opts {
		opt(derived)
	}
	hasCache, cacheTTL := src.copyRegistrationsTo(derived)

	if err := derived.loadFiles(); err != nil {
		return nil, fmt.Errorf("cannot derive configuration: %w", err)
	}

	// last, so that the caller's cache option wins and no cache is set up for an invalid file
	if hasCache && derived.defaultCache == nil {
		WithCachingEnabled(cacheTTL)(derived)
	}
	return derived, nil
}

// copyRegistrationsTo copies the registrations of ev to dst, where registrations already in dst win. It reports whether ev
// has a cache and the TTL of ev, read under the same lock.
func (ev *extendedViper) copyRegistrationsTo(dst *extendedViper) (bool, time.Duration) {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	if ev.automaticEnvEnabled {
		dst.AutomaticEnv()
	}
	for k, v := range ev.defaultValues {
		if _, ok := dst.defaultValues[k]; !ok {
			dst.defaultValues[k] = v
		}
	}
	for k, v := range ev.alternativeKeys {
		if _, ok := dst.alternativeKeys[k]; !ok {
			dst.alternativeKeys[k] = slices.Clone(v)
		}
	}
	for k, v := range ev.interkeyDependencies {
		dst.interkeyDependencies[k] = appendMissing(dst.interkeyDependencies[k], v...)
	}
	for k := range ev.persistedKeys {
		dst.persistedKeys[k] = true
	}
	dst.supportedEnvVars = appendMissing(dst.supportedEnvVars, ev.supportedEnvVars...)
	dst.supportedEnvVarPrefixes = appendMissing(dst.supportedEnvVarPrefixes, ev.supportedEnvVarPrefixes...)
	for _, flagset := range ev.flagsets {
		//nolint:errcheck // viper's BindPFlags returns nil for a non-nil flag set
		_ = dst.AddFlagSet(flagset)
	}
	return ev.defaultCache != nil, ev.cacheTTLValue()
}

// cacheTTLValue returns the TTL value of the configuration. The caller holds the lock; GetDuration cannot be used then.
func (ev *extendedViper) cacheTTLValue() time.Duration {
	ttl, err := toDuration(ev.viper.Get(CONFIG_CACHE_TTL))
	if err != nil {
		return 0
	}
	return ttl
}

// appendMissing appends the values not yet in list.
func appendMissing(list []string, values ...string) []string {
	for _, v := range values {
		if !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// Clone creates a copy of the current configuration.
func (ev *extendedViper) Clone() Configuration {
	// these lookups need to happen outside the critical section to avoid dealocks
	cacheTTL := ev.GetDuration(CONFIG_CACHE_TTL)

	// start critical section, everything within needs to be synchronized to safely clone.
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	// manually clone the Configuration instance
	options := []Opts{}
	if ev.configType == jsonFile {
		configFileUsed := ev.viper.ConfigFileUsed()
		options = append(options, WithFiles(configFileUsed))
	}

	clone := NewWithOpts(options...)
	clone.SetStorage(ev.storage)
	keys := ev.viper.AllKeys()
	for i := range keys {
		if isSet := ev.viper.IsSet(keys[i]); isSet {
			value := ev.viper.Get(keys[i])
			clone.Set(keys[i], value)
		}
	}

	for k, v := range ev.defaultValues {
		clone.AddDefaultValue(k, v)
	}

	if ev.automaticEnvEnabled {
		clone.AutomaticEnv()
	}
	clone.SetSupportedEnvVars(ev.supportedEnvVars...)
	clone.SetSupportedEnvVarPrefixes(ev.supportedEnvVarPrefixes...)
	clone.SetFiles(ev.configFiles...)

	for k, v := range ev.alternativeKeys {
		clone.AddAlternativeKeys(k, v)
	}

	for _, v := range ev.flagsets {
		//nolint:errcheck // breaking api change needed to fix this
		_ = clone.AddFlagSet(v)
	}

	if ev.defaultCache != nil {
		evClone, ok := clone.(*extendedViper)
		if !ok {
			panic("cloned configuration is of different type")
		}

		items := ev.defaultCache.Items()
		clonedCache := cache.NewFrom(cacheTTL, defaultCacheCleanupInterval, items)
		evClone.setCache(clonedCache)
		evClone.interkeyDependencies = ev.interkeyDependencies
	}

	return clone
}

func (ev *extendedViper) clearCache(key string) {
	if ev.defaultCache != nil {
		ev.defaultCache.Delete(key)

		// clear cache of all keys that depend on the current key
		for _, dependencyKey := range ev.interkeyDependencies[key] {
			ev.clearCache(dependencyKey)
		}
	}
}

// Set sets a configuration value.
func (ev *extendedViper) Set(key string, value interface{}) {
	ev.mutex.Lock()
	localStorage := ev.storage
	isPersisted := ev.persistedKeys[key]
	ev.viper.Set(key, value)
	ev.clearCache(key)

	ev.mutex.Unlock()

	if localStorage != nil && isPersisted {
		//nolint:errcheck // breaking api change needed to fix this
		_ = localStorage.Set(key, value)
	}
}

func (ev *extendedViper) get(key string) (result interface{}, err error) {
	err = ev.bindEnv(key)
	result = ev.viper.Get(key)
	isSet := ev.viper.IsSet(key)

	// try to lookup alternative keys if available
	index := 0
	alternativeKeys := ev.alternativeKeys[key]
	alternativeKeysSize := len(alternativeKeys)
	for !isSet && index < alternativeKeysSize {
		altKey := alternativeKeys[index]
		err = ev.bindEnv(altKey)
		result = ev.viper.Get(altKey)
		isSet = ev.viper.IsSet(altKey)
		index++
	}

	return result, err
}

// bindEnv extends Viper's BindEnv and will bind env vars to a key if it is a compatible GAF env var.
// Short-circuits before calling AllKeys() when the key cannot be an env var, avoiding
// Viper's expensive internal map rebuild on every lookup.
func (ev *extendedViper) bindEnv(key string) error {
	if ev.automaticEnvEnabled || ev.getKeyType(key) != EnvVarKeyType {
		return nil
	}

	// Viper's BindEnv implementation will bind the same env var multiple times, this check avoids potential duplication issues
	if slices.Contains(ev.viper.AllKeys(), key) {
		return nil
	}

	return ev.viper.BindEnv(key)
}

// IsSet returns true if a value for the given key was explicitly set
func (ev *extendedViper) IsSet(key string) bool {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	//nolint:errcheck // bindenv is actually best effort and we don't care about the error
	_ = ev.bindEnv(key)

	isSet := ev.viper.IsSet(key)
	if !isSet {
		for _, altKey := range ev.alternativeKeys[key] {
			isSet = ev.viper.IsSet(altKey)
		}
	}
	return isSet
}

// Unset removes a key and its alternatives from configuration when stored.
func (ev *extendedViper) Unset(key string) {
	// See https://github.com/spf13/viper/pull/519 for why this method will
	// probably never land in upstream viper. The author's reason for not doing
	// so seems to be, because removing a key is a persistence concern, which is
	// muddled in the viper API.
	//
	// Fair point but here is a pragmatic workaround.

	// If we're unsetting a key, we're intending to persist it.
	ev.PersistInStorage(key)

	// An empty struct marks the key for deletion in JsonStorage.
	ev.Set(key, keyDeleted)

	// Do the same for all this key's alternatives
	for _, otherKey := range ev.GetAlternativeKeys(key) {
		ev.PersistInStorage(otherKey)
		ev.Set(otherKey, keyDeleted)
	}
}

// Get returns a configuration value.
func (ev *extendedViper) Get(key string) interface{} {
	//nolint:errcheck // discarded error for callers who don't care
	value, _ := ev.GetWithError(key)
	return value
}

// GetWithError returns a configuration value and the potential error returned by the DefaultValueFunction for the configuration value.
func (ev *extendedViper) GetWithError(key string) (interface{}, error) {
	var err error
	var defaultFunc DefaultValueFunction
	var value interface{}
	var cacheDuration time.Duration
	var cacheEnabled bool
	var localDefaultCache *cache.Cache

	ev.mutex.Lock()
	defaultFunc = ev.defaultValues[key]

	// if enabled use cache
	cacheEnabled, cacheDuration = ev.getCacheSettings()

	if cacheEnabled {
		localDefaultCache = ev.defaultCache
		cachedValue, valueIsCached := localDefaultCache.Get(key)

		// return cached value if found
		if valueIsCached {
			ev.mutex.Unlock()
			return cachedValue, nil
		}
	}

	value, err = ev.get(key)
	ev.mutex.Unlock()

	// if nothing was found in the cache, try to execute the default function
	if defaultFunc != nil {
		var defErr error
		value, defErr = defaultFunc(ev, value)
		err = errors.Join(err, defErr)

		// if enabled and no error occurred, store value in cache
		if cacheEnabled && err == nil {
			localDefaultCache.Set(key, value, cacheDuration)
		}
	}

	return value, err
}

// GetStringWithError returns a configuration value as string.
func (ev *extendedViper) GetStringWithError(key string) (string, error) {
	result, err := ev.GetWithError(key)
	if err != nil {
		return "", err
	}

	switch v := result.(type) {
	case string:
		return v, nil
	case []string:
		if len(v) == 0 {
			return "", nil
		}

		return v[0], nil
	}

	return "", fmt.Errorf("value for key %s is not a string", key)
}

// GetString returns a configuration value as string.
func (ev *extendedViper) GetString(key string) string {
	result, err := ev.GetStringWithError(key)
	if err != nil {
		return ""
	}
	return result
}

// GetBoolWithError returns a configuration value as bool.
func (ev *extendedViper) GetBoolWithError(key string) (bool, error) {
	result, err := ev.GetWithError(key)
	if err != nil || result == nil {
		return false, err
	}

	return toBool(result)
}

// GetBool returns a configuration value as bool.
func (ev *extendedViper) GetBool(key string) bool {
	//nolint:errcheck // discarded error for callers who don't care
	result, _ := ev.GetBoolWithError(key)
	return result
}

// GetDurationWithError returns a configuration value as time.Duration.
func (ev *extendedViper) GetDurationWithError(key string) (time.Duration, error) {
	result, err := ev.GetWithError(key)
	if err != nil || result == nil {
		return 0, err
	}

	return toDuration(result)
}

// GetDuration returns a configuration value as time.Duration.
func (ev *extendedViper) GetDuration(key string) time.Duration {
	//nolint:errcheck // discarded error for callers who don't care
	result, _ := ev.GetDurationWithError(key)
	return result
}

// GetInt returns a configuration value as int.
func (ev *extendedViper) GetInt(key string) int {
	result := ev.Get(key)
	if result == nil {
		return 0
	}

	switch v := result.(type) {
	case string:
		stringResult := v
		i, err := strconv.ParseInt(stringResult, 10, 32)
		if err != nil {
			return 0
		}
		return int(i)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case int:
		return v
	}

	return 0
}

// GetFloat64 returns a configuration value as float64.
func (ev *extendedViper) GetFloat64(key string) float64 {
	result := ev.Get(key)
	if result == nil {
		return 0
	}

	switch v := result.(type) {
	case string:
		stringResult := v
		f, err := strconv.ParseFloat(stringResult, 64)
		if err != nil {
			return 0
		}
		return f
	case float32:
		return float64(v)
	case float64:
		return v
	case int:
		return float64(v)
	}

	return 0
}

// GetUrl returns a configuration value as url.URL.
func (ev *extendedViper) GetUrl(key string) *url.URL {
	urlString := ev.GetString(key)
	u, err := url.Parse(urlString)
	if err == nil {
		return u
	} else {
		return nil
	}
}

// AddFlagSet adds a flag set to the configuration.
func (ev *extendedViper) AddFlagSet(flagset *pflag.FlagSet) error {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()
	ev.flagsets = append(ev.flagsets, flagset)
	return ev.viper.BindPFlags(flagset)
}

// GetStringSlice returns a configuration value as []string.
func (ev *extendedViper) GetStringSlice(key string) []string {
	output := []string{}

	result := ev.Get(key)
	if result == nil {
		return output
	}

	switch v := result.(type) {
	case []string:
		return v
	// JSON arrays read back from a config file are decoded as []interface{}.
	case []interface{}:
		for _, item := range v {
			output = append(output, fmt.Sprintf("%v", item))
		}
		return output
	case string:
		if len(v) > 0 {
			return []string{v}
		}
		return output
	}

	return output
}

// AllKeys returns all keys of the configuration.
func (ev *extendedViper) AllKeys() []string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	keys := ev.viper.AllKeys()

	for k := range ev.defaultValues {
		keys = append(keys, k)
	}

	return keys
}

// AddDefaultValue adds a default value to the configuration.
func (ev *extendedViper) AddDefaultValue(key string, defaultValue DefaultValueFunction) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	ev.defaultValues[key] = defaultValue
}

// AddAlternativeKeys adds alternative keys to the configuration.
func (ev *extendedViper) AddAlternativeKeys(key string, altKeys []string) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()
	ev.alternativeKeys[key] = altKeys
}

// GetAlternativeKeys returns alternative keys from the configuration.
func (ev *extendedViper) GetAlternativeKeys(key string) []string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()
	return ev.alternativeKeys[key]
}

func (ev *extendedViper) PersistInStorage(key string) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()
	ev.persistedKeys[key] = true
}

func (ev *extendedViper) SetStorage(storage Storage) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()
	ev.storage = storage
}

func (ev *extendedViper) GetStorage() Storage {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()
	return ev.storage
}

// createFileStorage creates attempts to create a JSON file storage in the configPath.
// If it fails, a dummy storage is returned.
func (ev *extendedViper) createFileStorage(configPath string) Storage {
	file := path.Join(configPath, "snyk.json")
	return NewJsonStorage(file, WithConfiguration(ev))
}

// GetAllKeysThatContainValues returns a list of all keys, including alternative keys, that are set for the given key.
// This can be used to identify in which way a certain key has been set. If the result size is greater 1, this means
// that one value is specified multiple times.
func (ev *extendedViper) GetAllKeysThatContainValues(key string) []string {
	allKeys := ev.AllKeys()
	alternativeKeys := []string{key}
	alternativeKeys = append(alternativeKeys, ev.GetAlternativeKeys(key)...)

	foundKeys := []string{}
	for _, ak := range alternativeKeys {
		if ev.GetKeyType(ak) == EnvVarKeyType {
			if _, ok := os.LookupEnv(strings.ToUpper(ak)); ok {
				foundKeys = append(foundKeys, ak)
			}
		} else if slices.Contains(allKeys, ak) {
			if ev.viper.IsSet(ak) {
				foundKeys = append(foundKeys, ak)
			}
		}
	}

	return foundKeys
}

func (ev *extendedViper) GetKeyType(key string) KeyType {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	return ev.getKeyType(key)
}

func (ev *extendedViper) getKeyType(key string) KeyType {
	// check for supported env vars
	for _, envVar := range ev.supportedEnvVars {
		if strings.EqualFold(key, envVar) {
			return EnvVarKeyType
		}
	}

	// check for supported prefixes
	for _, prefix := range ev.supportedEnvVarPrefixes {
		if strings.HasPrefix(strings.ToLower(key), strings.ToLower(prefix)) {
			return EnvVarKeyType
		}
	}

	return UnspecifiedKeyType
}

// AutomaticEnv wraps Viper's AutomaticEnv and allows us to check if this has been set or not.
// If AutomaticEnv is enabled, SetSupportedEnvVars and SetSupportedEnvVarPrefixes is disabled.
func (ev *extendedViper) AutomaticEnv() {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	ev.viper.AutomaticEnv()
	ev.automaticEnvEnabled = true
}

func (ev *extendedViper) GetAutomaticEnv() bool {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	return ev.automaticEnvEnabled
}

// SetSupportedEnvVars sets the env vars that will be supported regardless of prefixes
// Only needed when SetAutomaticEnv is not used
func (ev *extendedViper) SetSupportedEnvVars(envVars ...string) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	for _, envVar := range envVars {
		if slices.Contains(ev.supportedEnvVars, envVar) {
			return
		}

		ev.supportedEnvVars = append(ev.supportedEnvVars, envVar)
	}
}

func (ev *extendedViper) GetSupportedEnvVars() []string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	return ev.supportedEnvVars
}

// SetSupportedEnvVarPrefixes sets prefixes which env vars must have to be supported
// Only needed when SetAutomaticEnv is not used
func (ev *extendedViper) SetSupportedEnvVarPrefixes(prefixes ...string) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	for _, prefix := range prefixes {
		if slices.Contains(ev.supportedEnvVarPrefixes, prefix) {
			return
		}

		ev.supportedEnvVarPrefixes = append(ev.supportedEnvVarPrefixes, prefix)
	}
}

func (ev *extendedViper) GetSupportedEnvVarPrefixes() []string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	return ev.supportedEnvVarPrefixes
}

// SetFiles sets the files from which the Configuration instance uses
func (ev *extendedViper) SetFiles(files ...string) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	ev.configFiles = append(ev.configFiles, files...)
}

func (ev *extendedViper) GetFiles() []string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	return ev.configFiles
}

func (ev *extendedViper) ReloadConfig() error {
	return ev.viper.ReadInConfig()
}

func (ev *extendedViper) ClearCache() {
	if ev.defaultCache != nil {
		ev.defaultCache.Flush()
	}
}

func (ev *extendedViper) setCache(c *cache.Cache) {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()
	ev.defaultCache = c
}

// getCacheSettings reads the cache-disabled and cache-TTL values through
// Viper so that values from any source (Set(), config files, SetDefault,
// AutomaticEnv-bound env vars) are honored.
// It uses ev.viper.Get() directly instead of ev.get() because the two
// internal cache keys have no alternative keys and no prefix-based env-var
// binding, so the extra bindEnv / IsSet / alternative-key overhead of
// ev.get() is unnecessary.
func (ev *extendedViper) getCacheSettings() (bool, time.Duration) {
	if ev.defaultCache == nil {
		return false, 0
	}

	raw := ev.viper.Get(CONFIG_CACHE_DISABLED)
	if disabled, err := toBool(raw); err == nil && disabled {
		return false, 0
	}

	raw = ev.viper.Get(CONFIG_CACHE_TTL)
	dur, err := toDuration(raw)
	if err != nil {
		return true, 0
	}
	return true, dur
}

func (ev *extendedViper) detectCircularDependency(key string, dependencyKey string) error {
	circularDependencyError := errors.New("circular dependency detected")

	if key == dependencyKey {
		return circularDependencyError
	}

	for _, existingKey := range ev.interkeyDependencies[key] {
		if existingKey == dependencyKey {
			return circularDependencyError
		}

		if err := ev.detectCircularDependency(existingKey, dependencyKey); err != nil {
			return err
		}
	}

	return nil
}

func (ev *extendedViper) AddKeyDependency(key string, dependencyKey string) error {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	// detect circular dependencies
	if err := ev.detectCircularDependency(key, dependencyKey); err != nil {
		return err
	}

	ev.interkeyDependencies[dependencyKey] = append(ev.interkeyDependencies[dependencyKey], key)
	return nil
}

func toBool(result interface{}) (bool, error) {
	switch v := result.(type) {
	case bool:
		return v, nil
	case string:
		boolResult, parseErr := strconv.ParseBool(v)
		if parseErr != nil {
			return false, parseErr
		}
		return boolResult, nil
	}

	return false, fmt.Errorf("value is not a bool")
}

func toDuration(result interface{}) (time.Duration, error) {
	switch v := result.(type) {
	case time.Duration:
		return v, nil
	case int:
		return time.Duration(v), nil
	case int64:
		return time.Duration(v), nil
	case string:
		return time.ParseDuration(v)
	}

	return 0, fmt.Errorf("value is not of type duration")
}
