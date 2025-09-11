package configuration

import (
	"errors"
	"fmt"
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

// WithCachingEnabled can be used to enable TTL based caching. Use NoCacheExpiration to keep values cached indefinitely.
func WithCachingEnabled(cacheDuration time.Duration) Opts {
	return func(c Configuration) {
		ev, ok := c.(*extendedViper)
		if !ok {
			panic("configuration must be used with WithCachingEnabled()")
		}

		localCache := cache.New(cacheDuration, defaultCacheCleanupInterval)
		ev.setCache(localCache)
		ev.Set(CONFIG_CACHE_DISABLED, false)
		ev.Set(CONFIG_CACHE_TTL, cacheDuration)
	}
}

// NewWithOpts creates a new snyk configuration file with optional parameters
func NewWithOpts(opts ...Opts) Configuration {
	config := createViperDefaultConfig(opts...)
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

func createViperDefaultConfig(opts ...Opts) *extendedViper {
	// prepare environment variables
	config := &extendedViper{
		viper:                viper.New(),
		alternativeKeys:      make(map[string][]string),
		defaultValues:        make(map[string]DefaultValueFunction),
		persistedKeys:        make(map[string]bool),
		interkeyDependencies: make(map[string][]string),
	}
	config.viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	for _, opt := range opts {
		opt(config)
	}

	if len(config.configFiles) > 0 {
		config.configType = jsonFile
		readConfigFilesIntoViper(config.configFiles, config)
	} else {
		config.configType = inMemory
	}

	return config
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
		clone.AddFlagSet(v)
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

// bindEnv extends Viper's BindEnv and will bind env vars to a key if it is a compatible GAF env var
func (ev *extendedViper) bindEnv(key string) error {
	isEnvVarKeyType := ev.getKeyType(key) == EnvVarKeyType
	isInAllKeys := slices.Contains(ev.viper.AllKeys(), key)

	// Viper's BindEnv implementation will bind the same env var multiple times, this check avoids potential duplication issues
	if !isEnvVarKeyType || isInAllKeys || ev.automaticEnvEnabled {
		return nil
	}

	return ev.viper.BindEnv(key)
}

// IsSet returns true if a value for the given key was explicitly set
func (ev *extendedViper) IsSet(key string) bool {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

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
	cacheEnabled, cacheDuration, err = ev.getCacheSettings()
	if err != nil {
		ev.mutex.Unlock()
		return nil, fmt.Errorf("failed to read cache settings %w", err)
	}

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

// return true if enabled and a caching duration
func (ev *extendedViper) getCacheSettings() (bool, time.Duration, error) {
	if ev.defaultCache == nil {
		return false, 0, nil
	}

	disabledRaw, err := ev.get(CONFIG_CACHE_DISABLED)
	if err != nil {
		return false, 0, err
	}

	durationRaw, err := ev.get(CONFIG_CACHE_TTL)
	if err != nil {
		return false, 0, err
	}

	enabled := true
	duration := time.Duration(0)
	if disabledRaw != nil {
		disabled, boolError := toBool(disabledRaw)
		if boolError != nil {
			return false, 0, boolError
		}

		enabled = !disabled
	}

	if durationRaw != nil {
		tmp, durError := toDuration(durationRaw)
		if durError != nil {
			return false, 0, durError
		}
		duration = tmp
	}

	return enabled, duration, nil
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
