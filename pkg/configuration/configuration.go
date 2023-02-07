package configuration

import (
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

//go:generate $GOPATH/bin/mockgen -source=configuration.go -destination ../mocks/configuration.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/

type DefaultValueFunction func(existingValue interface{}) interface{}

// Configuration is an interface for managing configuration values.
type Configuration interface {
	Clone() Configuration

	Set(key string, value interface{})
	Get(key string) interface{}
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
}

// extendedViper is a wrapper around the viper library.
// It adds support for default values and alternative keys.
type extendedViper struct {
	viper           *viper.Viper
	alternativeKeys map[string][]string
	defaultValues   map[string]DefaultValueFunction
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

// NewFromFiles creates a new Configuration instance from the given files.
func NewFromFiles(files ...string) Configuration {
	config := &extendedViper{
		viper:           viper.New(),
		alternativeKeys: make(map[string][]string),
		defaultValues:   make(map[string]DefaultValueFunction),
	}

	// prepare config files
	for _, file := range files {
		config.viper.SetConfigName(file)
	}

	configPath := determineBasePath()
	config.viper.AddConfigPath(configPath)
	config.viper.AddConfigPath(".")

	// prepare environment variables
	config.viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	config.viper.AutomaticEnv()

	// read config files
	config.viper.ReadInConfig()

	return config
}

// New creates a new snyk configuration file.
func New() Configuration {
	config := NewFromFiles("snyk")
	return config
}

// Clone creates a copy of the current configuration.
func (ev *extendedViper) Clone() Configuration {
	// manually clone the Configuration instance
	clone := NewFromFiles(ev.viper.ConfigFileUsed())
	keys := ev.viper.AllKeys()
	for i := range keys {
		value := ev.viper.Get(keys[i])
		clone.Set(keys[i], value)
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
	ev.viper.Set(key, value)
}

// Get returns a configuration value.
func (ev *extendedViper) Get(key string) interface{} {

	// try to lookup given key
	result := ev.viper.Get(key)

	// try to lookup alternative keys if available
	i := 0
	altKeys := ev.alternativeKeys[key]
	altKeysSize := len(altKeys)
	for result == nil && i < altKeysSize {
		tempKey := altKeys[i]
		result = ev.viper.Get(tempKey)
		i++
	}

	if ev.defaultValues[key] != nil {
		result = ev.defaultValues[key](result)
	}

	return result
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

	for k, _ := range ev.defaultValues {
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
