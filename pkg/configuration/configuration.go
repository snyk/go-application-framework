package configuration

import (
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

//go:generate $GOPATH/bin/mockgen -source=configuration.go -destination ../mocks/configuration.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/

type DefaultValueFunction func(existingValue interface{}) interface{}

type configType string

const inMemory configType = "in-memory"
const jsonFile configType = "json"

// Configuration is an interface for managing configuration values.
type Configuration interface {
	Clone() Configuration

	Set(key string, value interface{})
	Get(key string) interface{}
	IsSet(key string) bool
	GetString(key string) string
	GetStringSlice(key string) []string
	GetBool(key string) bool
	GetInt(key string) int
	GetFloat64(key string) float64
	GetUrl(key string) *url.URL

	AddFlagSet(flagset *pflag.FlagSet) error
	AllKeys() []string
	AddDefaultValue(key string, defaultValue DefaultValueFunction)
	AddAlternativeKeys(key string, altKeys []string)
	GetAlternativeKeys(key string) []string

	// PersistInStorage ensures that when Set is called with the given key, it will be persisted in the config file.
	PersistInStorage(key string)
	SetStorage(storage Storage)
	GetStorage() Storage
}

// extendedViper is a wrapper around the viper library.
// It adds support for default values and alternative keys.
type extendedViper struct {
	viper           *viper.Viper
	alternativeKeys map[string][]string
	defaultValues   map[string]DefaultValueFunction
	configType      configType

	// persistedKeys stores the keys that need to be persisted to storage when Set is called.
	// Only specific keys are persisted, so viper's native functionality is not used.
	persistedKeys map[string]bool
	storage       Storage
	mutex         sync.Mutex
}

// StandardDefaultValueFunction is a default value function that returns the default value if the existing value is nil.
func StandardDefaultValueFunction(defaultValue interface{}) DefaultValueFunction {
	return func(existingValue interface{}) interface{} {
		if existingValue != nil {
			return existingValue
		} else {
			return defaultValue
		}
	}
}

// determineBasePath returns the base path for the configuration files.
func determineBasePath() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}

	result := path.Join(homedir, ".config", "configstore")
	return result
}

// CreateConfigurationFile creates a configuration file with the given name.
func CreateConfigurationFile(filename string) (string, error) {
	configPath := determineBasePath()
	filepath := path.Join(configPath, filename)

	folder := path.Dir(filepath)
	err := os.MkdirAll(folder, 0755)
	if err != nil {
		return "", err
	}

	// create empty file
	err = os.WriteFile(filepath, []byte{}, 0755)
	if err != nil {
		return "", err
	}

	return filepath, err
}

// New creates a new snyk configuration file.
func New() Configuration {
	config := NewFromFiles("snyk")
	return config
}

// NewFromFiles creates a new Configuration instance from the given files.
func NewFromFiles(files ...string) Configuration {
	config := createViperDefaultConfig()
	config.configType = jsonFile
	readConfigFilesIntoViper(files, config)
	return config
}

func (ev *extendedViper) getConfigType() configType {
	return ev.configType
}

// NewInMemory creates a new Configuration instance that is not persisted to disk.
func NewInMemory() Configuration {
	config := createViperDefaultConfig()
	config.configType = inMemory
	return config
}

func createViperDefaultConfig() *extendedViper {
	// prepare environment variables
	config := &extendedViper{
		viper:           viper.New(),
		alternativeKeys: make(map[string][]string),
		defaultValues:   make(map[string]DefaultValueFunction),
		persistedKeys:   make(map[string]bool),
	}
	config.viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	config.viper.AutomaticEnv()
	return config
}

func readConfigFilesIntoViper(files []string, config *extendedViper) {
	configPath := determineBasePath()
	config.storage = createFileStorage(configPath)

	// prepare config files
	for _, file := range files {
		config.viper.SetConfigName(file)
	}

	config.viper.AddConfigPath(configPath)
	config.viper.AddConfigPath(".")

	// read config files
	_ = config.viper.ReadInConfig()
}

// Clone creates a copy of the current configuration.
func (ev *extendedViper) Clone() Configuration {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	// manually clone the Configuration instance
	var clone Configuration
	if ev.configType == jsonFile {
		configFileUsed := ev.viper.ConfigFileUsed()
		clone = NewFromFiles(configFileUsed)
	} else {
		clone = NewInMemory()
	}

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

	for k, v := range ev.alternativeKeys {
		clone.AddAlternativeKeys(k, v)
	}

	return clone
}

// Set sets a configuration value.
func (ev *extendedViper) Set(key string, value interface{}) {
	ev.mutex.Lock()

	ev.viper.Set(key, value)

	ev.mutex.Unlock()

	if ev.storage != nil && ev.persistedKeys[key] {
		_ = ev.storage.Set(key, value)
	}
}

func (ev *extendedViper) get(key string) interface{} {
	ev.mutex.Lock()
	defer ev.mutex.Unlock()

	// try to lookup given key
	result := ev.viper.Get(key)
	isSet := ev.viper.IsSet(key)

	// try to lookup alternative keys if available
	if !isSet {
		for _, altKey := range ev.alternativeKeys[key] {
			result = ev.viper.Get(altKey)
		}
	}

	return result
}

// returns true if a value for the given key was explicitly set
func (ev *extendedViper) IsSet(key string) bool {
	isSet := ev.viper.IsSet(key)
	if !isSet {
		for _, altKey := range ev.alternativeKeys[key] {
			isSet = ev.viper.IsSet(altKey)
		}
	}
	return isSet
}

// Get returns a configuration value.
func (ev *extendedViper) Get(key string) interface{} {
	// use synchronized get()
	value := ev.get(key)

	if ev.defaultValues[key] != nil {
		value = ev.defaultValues[key](value)
	}

	return value
}

// GetString returns a configuration value as string.
func (ev *extendedViper) GetString(key string) string {
	result := ev.Get(key)
	if result == nil {
		return ""
	}
	return result.(string)
}

// GetBool returns a configuration value as bool.
func (ev *extendedViper) GetBool(key string) bool {
	result := ev.Get(key)
	if result == nil {
		return false
	}

	switch result.(type) {
	case bool:
		return result.(bool)
	case string:
		stringResult := result.(string)
		boolResult, _ := strconv.ParseBool(stringResult)
		return boolResult
	}

	return false
}

// GetInt returns a configuration value as int.
func (ev *extendedViper) GetInt(key string) int {
	result := ev.Get(key)
	if result == nil {
		return 0
	}

	switch result.(type) {
	case string:
		stringResult := result.(string)
		temp, _ := strconv.ParseInt(stringResult, 10, 32)
		return int(temp)
	case float32:
		return int(result.(float32))
	case float64:
		return int(result.(float64))
	case int:
		return int(result.(int))
	}

	return 0
}

// GetFloat64 returns a configuration value as float64.
func (ev *extendedViper) GetFloat64(key string) float64 {
	result := ev.Get(key)
	if result == nil {
		return 0
	}

	switch result.(type) {
	case string:
		stringResult := result.(string)
		temp, _ := strconv.ParseFloat(stringResult, 64)
		return float64(temp)
	case float32:
		return float64(result.(float32))
	case float64:
		return float64(result.(float64))
	case int:
		return float64(result.(int))
	}

	return 0
}

// GetUrl returns a configuration value as url.URL.
func (ev *extendedViper) GetUrl(key string) *url.URL {
	urlString := ev.GetString(key)
	url, err := url.Parse(urlString)
	if err == nil {
		return url
	} else {
		return nil
	}
}

// AddFlagSet adds a flag set to the configuration.
func (ev *extendedViper) AddFlagSet(flagset *pflag.FlagSet) error {
	return ev.viper.BindPFlags(flagset)
}

// GetStringSlice returns a configuration value as []string.
func (ev *extendedViper) GetStringSlice(key string) []string {
	output := []string{}

	result := ev.Get(key)
	if result == nil {
		return output
	}

	switch result.(type) {
	case []string:
		return result.([]string)
	}

	return output
}

// AllKeys returns all keys of the configuration.
func (ev *extendedViper) AllKeys() []string {
	keys := ev.viper.AllKeys()

	for k := range ev.defaultValues {
		keys = append(keys, k)
	}

	return keys
}

// AddDefaultValue adds a default value to the configuration.
func (ev *extendedViper) AddDefaultValue(key string, defaultValue DefaultValueFunction) {
	ev.defaultValues[key] = defaultValue
}

// AddAlternativeKeys adds alternative keys to the configuration.
func (ev *extendedViper) AddAlternativeKeys(key string, altKeys []string) {
	ev.alternativeKeys[key] = altKeys
}

// GetAlternativeKeys returns alternative keys from the configuration.
func (ev *extendedViper) GetAlternativeKeys(key string) []string {
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
	ev.mutex.Lock()
	defer ev.mutex.Unlock()
	return ev.storage
}

// createFileStorage creates attempts to create a JSON file storage in the configPath.
// If it fails, a dummy storage is returned.
func createFileStorage(configPath string) Storage {
	file := path.Join(configPath, "snyk.json")
	return NewJsonStorage(file)
}
