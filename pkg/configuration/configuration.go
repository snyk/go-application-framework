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

type extendedViper struct {
	viper           *viper.Viper
	alternativeKeys map[string][]string
	defaultValues   map[string]DefaultValueFunction
}

func StandardDefaultValueFunction(defaultValue interface{}) DefaultValueFunction {
	return func(existingValue interface{}) interface{} {
		if existingValue != nil {
			return existingValue
		} else {
			return defaultValue
		}
	}
}

func determineBasePath() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}

	result := path.Join(homedir, ".config", "configstore")
	return result
}

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

func New() Configuration {
	config := NewFromFiles("snyk")
	return config
}

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

func (ev *extendedViper) Set(key string, value interface{}) {
	ev.viper.Set(key, value)
}

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

func (ev *extendedViper) GetString(key string) string {
	result := ev.Get(key)
	if result == nil {
		return ""
	}
	return result.(string)
}

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

func (ev *extendedViper) GetUrl(key string) *url.URL {
	urlString := ev.GetString(key)
	url, err := url.Parse(urlString)
	if err == nil {
		return url
	} else {
		return nil
	}
}

func (ev *extendedViper) AddFlagSet(flagset *pflag.FlagSet) error {
	return ev.viper.BindPFlags(flagset)
}

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

func (ev *extendedViper) AllKeys() []string {
	keys := ev.viper.AllKeys()

	for k := range ev.defaultValues {
		keys = append(keys, k)
	}

	return keys
}

func (ev *extendedViper) AddDefaultValue(key string, defaultValue DefaultValueFunction) {
	ev.defaultValues[key] = defaultValue
}

func (ev *extendedViper) AddAlternativeKeys(key string, altKeys []string) {
	ev.alternativeKeys[key] = altKeys
}
