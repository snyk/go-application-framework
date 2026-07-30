// Package configtypes holds the Configuration and Storage contracts in a package of their own,
// so pkg/configuration's own dependencies can accept a Configuration without an import cycle.
// pkg/configuration aliases these types; prefer those aliases and import this package directly
// only when pkg/configuration is out of reach.
package configtypes

import (
	"net/url"
	"time"

	"github.com/spf13/pflag"
)

type KeyType int

const (
	EnvVarKeyType      KeyType = iota
	UnspecifiedKeyType KeyType = iota
)

// DefaultValueFunction derives the value of a configuration key when it has not been set explicitly.
type DefaultValueFunction func(config Configuration, existingValue interface{}) (interface{}, error)

//go:generate go tool github.com/golang/mock/mockgen -source=configuration.go -destination ../../mocks/configuration.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/configtypes/

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
