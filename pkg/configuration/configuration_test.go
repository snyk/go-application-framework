package configuration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

const (
	TEST_FILENAME      string = "test"
	TEST_FILENAME_JSON string = "test.json"
)

func prepareConfigstore(content string) error {
	file, err := CreateConfigurationFile(TEST_FILENAME_JSON)
	if err != nil {
		return err
	}

	// write content to file
	err = os.WriteFile(file, []byte(content), 0755)
	return err
}

func cleanupConfigstore(t *testing.T) {
	t.Helper()
	file, err := CreateConfigurationFile(TEST_FILENAME_JSON)
	assert.NoError(t, err)
	err = os.RemoveAll(file)
	assert.NoError(t, err)
}

func cleanUpEnvVars() {
	os.Unsetenv("SNYK_TOKEN")
	os.Unsetenv("SNYK_OAUTH_TOKEN")
	os.Unsetenv("SNYK_DOCKER_TOKEN")
	os.Unsetenv("SNYK_DISABLE_ANALYTICS")
}

func Test_ConfigurationGet_AUTHENTICATION_TOKEN(t *testing.T) {
	os.Unsetenv("SNYK_TOKEN")
	expectedValue := "mytoken"
	expectedValue2 := "123456"
	assert.Nil(t, prepareConfigstore(`{"api": "mytoken", "somethingElse": 12}`))

	config := NewWithOpts(
		WithFiles("test"),
		WithSupportedEnvVarPrefixes("snyk_"),
	)
	config.AddAlternativeKeys(AUTHENTICATION_TOKEN, []string{"snyk_token", "snyk_cfg_api", "api"})

	actualValue := config.GetString(AUTHENTICATION_TOKEN)
	assert.Equal(t, expectedValue, actualValue)

	t.Setenv("SNYK_TOKEN", expectedValue2)
	actualValue = config.GetString(AUTHENTICATION_TOKEN)
	assert.Equal(t, expectedValue2, actualValue)

	cleanupConfigstore(t)
	cleanUpEnvVars()
}

func Test_ConfigurationGet_AUTHENTICATION_BEARER_TOKEN(t *testing.T) {
	expectedValue := "anotherToken"
	expectedValueDocker := "dockerToken"
	assert.Nil(t, prepareConfigstore(`{"api": "mytoken", "somethingElse": 12}`))

	config := NewWithOpts(
		WithFiles(TEST_FILENAME),
		WithSupportedEnvVarPrefixes("snyk_"),
	)
	config.AddAlternativeKeys(AUTHENTICATION_BEARER_TOKEN, []string{"snyk_oauth_token", "snyk_docker_token"})

	t.Run("oauth token", func(t *testing.T) {
		t.Setenv("SNYK_OAUTH_TOKEN", expectedValue)
		actualValue := config.GetString(AUTHENTICATION_BEARER_TOKEN)
		assert.Equal(t, expectedValue, actualValue)
	})

	t.Run("docker token", func(t *testing.T) {
		t.Setenv("SNYK_DOCKER_TOKEN", expectedValueDocker)
		actualValue := config.GetString(AUTHENTICATION_BEARER_TOKEN)
		assert.Equal(t, expectedValueDocker, actualValue)
	})

	cleanupConfigstore(t)
	cleanUpEnvVars()
}

func Test_ConfigurationGet_ANALYTICS_DISABLED(t *testing.T) {
	assert.Nil(t, prepareConfigstore(`{"snyk_oauth_token": "mytoken", "somethingElse": 12}`))

	config := NewWithOpts(
		WithFiles(TEST_FILENAME),
		WithSupportedEnvVarPrefixes("snyk_"),
	)

	t.Setenv("SNYK_DISABLE_ANALYTICS", "1")
	actualValue := config.GetBool(ANALYTICS_DISABLED)
	assert.True(t, actualValue)

	t.Setenv("SNYK_DISABLE_ANALYTICS", "0")
	actualValue = config.GetBool(ANALYTICS_DISABLED)
	assert.False(t, actualValue)

	cleanupConfigstore(t)
	cleanUpEnvVars()
}

func Test_Configuration_GetE(t *testing.T) {
	assert.Nil(t, prepareConfigstore(`{"snyk_oauth_token": "mytoken", "somethingElse": 12}`))

	config := NewWithOpts(
		WithFiles(TEST_FILENAME),
		WithSupportedEnvVarPrefixes("snyk_"),
	)

	_ = os.Unsetenv(ANALYTICS_DISABLED)

	actualValue, err := config.GetWithError(ANALYTICS_DISABLED)
	assert.Nil(t, err)
	assert.Nil(t, actualValue)

	t.Setenv("SNYK_DISABLE_ANALYTICS", "1")
	actualValue, err = config.GetWithError(ANALYTICS_DISABLED)
	assert.Nil(t, err)
	assert.NotNil(t, actualValue)
	assert.Equal(t, "1", actualValue)

	t.Setenv("SNYK_DISABLE_ANALYTICS", "0")
	actualValue, err = config.GetWithError(ANALYTICS_DISABLED)
	assert.Nil(t, err)
	assert.NotNil(t, actualValue)
	assert.Equal(t, "0", actualValue)

	cleanupConfigstore(t)
	cleanUpEnvVars()
}

func Test_ConfigurationGet_ALTERNATE_KEYS(t *testing.T) {
	key := "snyk_cfg_api"
	expected := "value"
	alternateKeys := []string{"snyk_token", "snyk_cfg_api", "api"}

	config := NewInMemory()
	config.AddAlternativeKeys(AUTHENTICATION_TOKEN, alternateKeys)

	config.Set(key, expected)

	actualValue := config.GetAlternativeKeys(AUTHENTICATION_TOKEN)
	assert.Equal(t, alternateKeys, actualValue)

	actual := config.GetString(AUTHENTICATION_TOKEN)
	assert.Equal(t, expected, actual)
}

func Test_ConfigurationGet_unset(t *testing.T) {
	assert.Nil(t, prepareConfigstore(`{"api": "mytoken", "somethingElse": 12}`))

	config := NewWithOpts(WithFiles(TEST_FILENAME))
	actualValue := config.Get("notthere")
	assert.Nil(t, actualValue)

	actualValueString := config.GetString("notthere")
	assert.Empty(t, actualValueString)

	actualValueBool := config.GetBool("notthere")
	assert.False(t, actualValueBool)

	cleanupConfigstore(t)
}

func Test_ConfigurationSet_differentCases(t *testing.T) {
	assert.Nil(t, prepareConfigstore(`{"api": "mytoken", "somethingElse": 12, "number": 74}`))

	config := NewWithOpts(
		WithFiles(TEST_FILENAME),
		WithSupportedEnvVarPrefixes("snyk_"),
	)

	actualValueString := config.GetString("api")
	assert.Equal(t, "mytoken", actualValueString)

	actualValueInt := config.GetInt("somethingElse")
	assert.Equal(t, 12, actualValueInt)

	actualValueFloat := config.GetFloat64("number")
	assert.Equal(t, 74.0, actualValueFloat)

	config.Set("api", "newToken")
	config.Set("somethingElse", 798)
	config.Set("number", "798.36")

	actualValueString = config.GetString("api")
	assert.Equal(t, "newToken", actualValueString)

	actualValueInt = config.GetInt("somethingElse")
	assert.Equal(t, 798, actualValueInt)

	actualValueFloat = config.GetFloat64("number")
	assert.Equal(t, 798.36, actualValueFloat)

	// assert existing behavior: invalid float is 0
	actualValueFloat = config.GetFloat64("api")
	assert.Equal(t, 0.0, actualValueFloat)

	// assert existing behavior: invalid int is 0
	actualValueInt = config.GetInt("api")
	assert.Equal(t, 0, actualValueInt)

	t.Run("only read env vars prefixed with SNYK_", func(t *testing.T) {
		defaultValue := "something"
		key := "SNYK_CFG_ORG"
		expected := "hello"
		wrongKey := "ORG"
		notExpected := "notAValidEnvVar"
		flagset := pflag.NewFlagSet("test", pflag.ExitOnError)
		flagset.String(ORGANIZATION, "", "org")

		config := NewWithOpts(WithSupportedEnvVarPrefixes("snyk_"))
		err := config.AddFlagSet(flagset)
		assert.NoError(t, err)
		config.AddAlternativeKeys(ORGANIZATION, []string{"snyk_cfg_org"})
		config.AddDefaultValue(ORGANIZATION, func(existingValue interface{}) (interface{}, error) {
			if existingValue != nil {
				return existingValue, nil
			}
			return defaultValue, nil
		})

		// not set
		actual := config.GetString(ORGANIZATION)
		wasSet := config.IsSet(ORGANIZATION)
		assert.Equal(t, defaultValue, actual)
		assert.False(t, wasSet)

		// set via env var
		t.Setenv(key, expected)
		t.Setenv(wrongKey, notExpected)
		actual = config.GetString(ORGANIZATION)
		wasSet = config.IsSet(ORGANIZATION)
		assert.Equal(t, expected, actual)
		assert.True(t, wasSet)
	})

	cleanupConfigstore(t)
}

func Test_ConfigurationGet_Url(t *testing.T) {
	assert.Nil(t, prepareConfigstore(`{"validUrl": "https://www.snyk.io", "invalidUrl": "something"}`))

	config := NewFromFiles(TEST_FILENAME)

	validUrl := config.GetUrl("validUrl")
	assert.NotNil(t, validUrl)

	invalidUrl := config.GetUrl("invalidUrl")
	assert.NotNil(t, invalidUrl)
}

func Test_ConfigurationGet_StringSlice(t *testing.T) {
	config := New()

	expectedDefault := []string{}

	actual := config.GetStringSlice(RAW_CMD_ARGS)
	assert.Equal(t, expectedDefault, actual)

	expectedNew := []string{"1", "2", "go"}
	config.Set(RAW_CMD_ARGS, expectedNew)

	actualNew := config.GetStringSlice(RAW_CMD_ARGS)
	assert.Equal(t, expectedNew, actualNew)

	actualEmpty := config.GetStringSlice(API_URL)
	assert.Empty(t, actualEmpty)
}

func Test_ConfigurationClone(t *testing.T) {
	assert.Nil(t, prepareConfigstore(`{"api": "mytoken", "somethingElse": 12, "number": 74}`))
	flagset := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flagset.Bool("debug", true, "debugging")
	flagset.Float64("size", 10, "size")

	config := NewFromFiles(TEST_FILENAME)
	err := config.AddFlagSet(flagset)
	assert.NoError(t, err)

	// test cloning of default values
	defaultValueKey := "MyDefault"
	expectedDefaultValue := "-my-default-"
	config.AddDefaultValue(defaultValueKey, StandardDefaultValueFunction(expectedDefaultValue))

	// test cloning of alternate keys
	expectedAlternateValue := "bla"
	notExistingKey := "notExisting"
	alternateValueKey := "AlternateMyDefault"
	config.Set(alternateValueKey, expectedAlternateValue)
	config.AddAlternativeKeys(notExistingKey, []string{alternateValueKey})

	actualValueString := config.GetString("api")
	assert.Equal(t, "mytoken", actualValueString)

	// create the clone
	clonedConfig := config.Clone()

	// manipulate the token
	clonedConfig.Set("api", "10987654321")

	// ensure that the token isn't changed in the original instance
	actualValueString = config.GetString("api")
	assert.Equal(t, "mytoken", actualValueString)

	actualValueString = clonedConfig.GetString("api")
	assert.Equal(t, "10987654321", actualValueString)

	originalKeys := config.AllKeys()
	clonedKeys := clonedConfig.AllKeys()
	sort.Strings(originalKeys)
	sort.Strings(clonedKeys)

	assert.Equal(t, originalKeys, clonedKeys)

	for i := range originalKeys {
		key := originalKeys[i]
		fmt.Println("- key:", key)
		if key != "api" {
			originalValue := config.Get(key)
			clonedValue := clonedConfig.Get(key)
			assert.Equal(t, originalValue, clonedValue)

			originalValueIsSet := config.IsSet(key)
			clonedValueIsSet := clonedConfig.IsSet(key)
			assert.Equal(t, originalValueIsSet, clonedValueIsSet)
		}
	}

	actualDefaultValue := clonedConfig.GetString(defaultValueKey)
	assert.Equal(t, expectedDefaultValue, actualDefaultValue)

	actualAlternateValue := clonedConfig.GetString(notExistingKey)
	assert.Equal(t, expectedAlternateValue, actualAlternateValue)

	// we assume that a cloned configuration uses the same storage object. Just the pointer is cloned.
	assert.Equal(t, config.(*extendedViper).storage, clonedConfig.(*extendedViper).storage)

	cleanupConfigstore(t)
}

func TestNewInMemory(t *testing.T) {
	config := NewInMemory()
	ev, ok := config.(*extendedViper)
	assert.True(t, ok)
	assert.Nil(t, ev.storage)
	assert.NotNil(t, config)
	assert.Equal(t, inMemory, ev.getConfigType())
}

func TestNewFromFiles(t *testing.T) {
	config := NewFromFiles(filepath.Join(t.TempDir(), t.Name()))
	ev, ok := config.(*extendedViper)
	assert.True(t, ok)
	assert.NotNil(t, config)
	assert.Equal(t, jsonFile, ev.getConfigType())
}

func TestNewInMemory_shouldNotBreakWhenTryingToPersist(t *testing.T) {
	config := NewInMemory()

	assert.Nil(t, config.(*extendedViper).storage)
	assert.NotNil(t, config)

	const key = "test"
	const keyValue = "keyValue"
	config.PersistInStorage(key)
	config.Set(key, keyValue)

	assert.Equal(t, config.Get(key), keyValue)
}

func Test_DefaultValuehandling(t *testing.T) {
	t.Run("set value in code", func(t *testing.T) {
		keyNoDefault := "name"
		keyWithDefault := "last name"
		valueWithDefault := "default"
		valueExplicitlySet := "explicitly set value"

		config := NewInMemory()
		config.AddDefaultValue(keyWithDefault, func(existingValue interface{}) (interface{}, error) {
			if existingValue != nil {
				return existingValue, nil
			}
			return valueWithDefault, nil
		})

		// access value that has a default value
		actualValue := config.GetString(keyWithDefault)
		actualWasSet := config.IsSet(keyWithDefault)
		assert.Equal(t, valueWithDefault, actualValue)
		assert.False(t, actualWasSet)

		// access value that has a default value but is explicitly set
		config.Set(keyWithDefault, valueExplicitlySet)
		actualValue = config.GetString(keyWithDefault)
		actualWasSet = config.IsSet(keyWithDefault)
		assert.Equal(t, valueExplicitlySet, actualValue)
		assert.True(t, actualWasSet)

		// access value that has NO default value
		actualValueI := config.Get(keyNoDefault)
		actualWasSet = config.IsSet(keyNoDefault)
		assert.Nil(t, actualValueI)
		assert.False(t, actualWasSet)
	})

	t.Run("set value as env", func(t *testing.T) {
		key := "SNYK_CFG_ORG"
		expected := "hello"
		defaultValue := "something"
		flagset := pflag.NewFlagSet("test", pflag.ExitOnError)
		flagset.String(ORGANIZATION, "", "org")

		config := NewWithOpts(WithSupportedEnvVarPrefixes("snyk_"))
		err := config.AddFlagSet(flagset)
		assert.NoError(t, err)
		config.AddAlternativeKeys(ORGANIZATION, []string{"snyk_cfg_org"})
		config.AddDefaultValue(ORGANIZATION, func(existingValue interface{}) (interface{}, error) {
			if existingValue != nil {
				return existingValue, nil
			}
			return defaultValue, nil
		})

		// not set
		actual := config.GetString(ORGANIZATION)
		wasSet := config.IsSet(ORGANIZATION)
		assert.Equal(t, defaultValue, actual)
		assert.False(t, wasSet)

		// set via env var
		t.Setenv(key, expected)
		actual = config.GetString(ORGANIZATION)
		wasSet = config.IsSet(ORGANIZATION)
		assert.Equal(t, expected, actual)
		assert.True(t, wasSet)
	})

	t.Run("set and unset", func(t *testing.T) {
		fakehome := t.TempDir()
		t.Setenv("HOME", fakehome)
		t.Setenv("USERPROFILE", fakehome)
		configPath := filepath.Join(fakehome, ".config", "configstore", TEST_FILENAME_JSON)

		assert.NoError(t, prepareConfigstore(`{"foo":"bar","baz":"quux"}`))
		config := NewFromFiles(TEST_FILENAME)
		config.SetStorage(NewJsonStorage(configPath))
		config.AddAlternativeKeys("foo", []string{"foof", "floof"})

		assert.Equal(t, "bar", config.Get("foo"))
		assert.Equal(t, "quux", config.Get("baz"))

		config.Unset("foo")

		contents, err := os.ReadFile(configPath)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"baz":"quux"}`, string(contents))

		config = NewFromFiles(TEST_FILENAME)
		assert.Equal(t, nil, config.Get("foo"))
		assert.Equal(t, "quux", config.Get("baz"))
	})
}

func Test_ConfigurationGet_GetAllKeysThatContainValues(t *testing.T) {
	// prepare values
	t.Setenv(strings.ToUpper(API_URL), "something")
	flagset := pflag.NewFlagSet("test set", pflag.ExitOnError)
	flagset.String("token", "nothing", "")
	flagset.Bool("debug", false, "")
	assert.Nil(t, prepareConfigstore(`{"api": "mytoken", "endpoint": "https://api.snyk.io"}`))

	// prepare configuration under test
	config := NewFromFiles(TEST_FILENAME)
	err := config.AddFlagSet(flagset)
	assert.NoError(t, err)

	config.AddAlternativeKeys(API_URL, []string{"endpoint"})
	config.AddAlternativeKeys(AUTHENTICATION_TOKEN, []string{"api", "token"})

	config.Set(API_URL, "dasjlda")
	config.Set("token", "secret")
	config.Set("debug", true)

	// run method under test
	apiUrlKeys := config.GetAllKeysThatContainValues(API_URL)
	tokenKeys := config.GetAllKeysThatContainValues(AUTHENTICATION_TOKEN)
	debugKeys := config.GetAllKeysThatContainValues(DEBUG)

	expectedApiUrlKeys := []string{"snyk_api", "endpoint"}
	expectedTokenKeys := []string{"api", "token"}
	expectedDebugKeys := []string{"debug"}

	assert.Equal(t, expectedApiUrlKeys, apiUrlKeys)
	assert.Equal(t, expectedTokenKeys, tokenKeys)
	assert.Equal(t, expectedDebugKeys, debugKeys)
}

func Test_Configuration_GetKeyType(t *testing.T) {
	config := NewWithOpts(
		WithSupportedEnvVarPrefixes("snyk_"),
	)
	assert.Equal(t, EnvVarKeyType, config.GetKeyType("snyk_something"))
	assert.Equal(t, UnspecifiedKeyType, config.GetKeyType("app"))
}

func Test_Configuration_Locking(t *testing.T) {
	t.Run("locks env var gets", func(t *testing.T) {
		var wg sync.WaitGroup
		N := 100

		config := NewWithOpts(WithSupportedEnvVarPrefixes("test_"), WithCachingEnabled(3*time.Second))

		for i := range N {
			wg.Add(1)
			go func() {
				defer wg.Done()

				key := fmt.Sprintf("test_%d", i)
				config.AddDefaultValue(key, StandardDefaultValueFunction(2))
				_ = config.Get(key)
			}()
		}

		wg.Wait()
	})

	t.Run("locks gets", func(t *testing.T) {
		var wg sync.WaitGroup
		N := 100

		config := New()

		for i := range N {
			wg.Add(1)
			go func() {
				defer wg.Done()

				key := fmt.Sprintf("%d", i)
				_ = config.Get(key)
			}()
		}

		wg.Wait()
	})
}

func Test_JsonStorage_Locking(t *testing.T) {
	outerConfig := NewFromFiles(TEST_FILENAME)
	outerConfig.PersistInStorage("n")
	outerConfig.Set("n", float64(0))
	N := 100
	ch := make(chan struct{}, N)
	ctx := context.Background()
	for i := 0; i < N; i++ {
		go func() {
			defer func() { ch <- struct{}{} }()

			config := NewFromFiles(TEST_FILENAME)
			config.PersistInStorage("n")
			storage := config.GetStorage()
			assert.NotNil(t, storage)

			err := storage.Lock(ctx, time.Millisecond)
			assert.NoError(t, err)
			defer func() {
				unlockErr := storage.Unlock()
				assert.NoError(t, unlockErr)
			}()

			err = storage.Refresh(config, "n")
			assert.NoError(t, err)
			config.Set("n", config.GetFloat64("n")+1)
		}()
	}
	for i := 0; i < N; i++ {
		<-ch
	}
	// Before refresh, we still have the initial value.
	assert.Equal(t, float64(0), outerConfig.GetFloat64("n"))
	err := outerConfig.GetStorage().Refresh(outerConfig, "n")
	assert.NoError(t, err)
	// After refresh, we get the sum from all the concurrent goroutines.
	assert.Equal(t, float64(N), outerConfig.GetFloat64("n"))
}

func Test_JsonStorage_Locking_Interrupted(t *testing.T) {
	outerConfig := NewFromFiles(TEST_FILENAME)
	outerConfig.PersistInStorage("n")
	outerConfig.Set("n", float64(0))
	N := 100
	ch := make(chan struct{}, N)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < N; i++ {
		go func() {
			defer func() { ch <- struct{}{} }()

			config := NewFromFiles(TEST_FILENAME)
			config.PersistInStorage("n")
			storage := config.GetStorage()
			assert.NotNil(t, storage)

			err := storage.Lock(ctx, time.Millisecond)
			if err != nil {
				assert.ErrorIs(t, err, context.Canceled)
				return
			} else {
				assert.NoError(t, err)
			}
			defer func() {
				unlockErr := storage.Unlock()
				assert.NoError(t, unlockErr)
			}()

			err = storage.Refresh(config, "n")
			assert.NoError(t, err)
			n := config.GetFloat64("n")
			if n == 50 {
				// Locking will fail after 50 increments.
				// All subsequent attempts will fail to lock.
				cancel()
				return
			}
			config.Set("n", config.GetFloat64("n")+1)
		}()
	}
	for i := 0; i < N; i++ {
		<-ch
	}
	// Before refresh, we still have the initial value.
	assert.Equal(t, float64(0), outerConfig.GetFloat64("n"))
	err := outerConfig.GetStorage().Refresh(outerConfig, "n")
	assert.NoError(t, err)
	// After refresh, we get the sum from all the concurrent goroutines prior
	// to the context getting canceled.
	assert.Equal(t, float64(50), outerConfig.GetFloat64("n"))
}

func Test_Configuration_envVarSupport(t *testing.T) {
	t.Run("supports a list of prefixes", func(t *testing.T) {
		config := NewWithOpts(WithSupportedEnvVarPrefixes("snyk_", "internal_"))

		snykKey := "SNYK_TOKEN"
		snykValue := "someSnykToken"
		snykInternalKey := "INTERNAL_SNYK_OAUTH_ENABLED"
		snykInternalValue := "true"
		invalidKey := "NOT_SUPPORTED"
		invalidKeyValue := "thisShouldFail"

		t.Setenv(snykKey, snykValue)
		t.Setenv(snykInternalKey, snykInternalValue)
		t.Setenv(invalidKey, invalidKeyValue)

		actualSnykKeyValue := config.GetString(snykKey)
		assert.Equal(t, snykValue, actualSnykKeyValue)

		actualSnykInternalValue := config.GetBool(snykInternalKey)
		assert.True(t, actualSnykInternalValue)

		shouldBeNil := config.Get(invalidKey)
		assert.Nil(t, shouldBeNil)

		cleanUpEnvVars()
	})

	t.Run("supports a list of env vars", func(t *testing.T) {
		config := NewWithOpts(WithSupportedEnvVars("NODE_EXTRA_CA_CERTS", "ORG"))

		nodeCertsKey := "NODE_EXTRA_CA_CERTS"
		nodeCertsValue := "some/path/to/certs"
		orgKey := "ORG"
		orgValue := "someOrg"

		t.Setenv(nodeCertsKey, nodeCertsValue)
		t.Setenv(orgKey, orgValue)

		actualNodeCertsValue := config.GetString(nodeCertsKey)
		actualOrgValue := config.GetString(orgKey)

		assert.Equal(t, nodeCertsValue, actualNodeCertsValue)
		assert.Equal(t, orgValue, actualOrgValue)
	})

	t.Run("supports a list of env vars and prefixes", func(t *testing.T) {
		config := NewWithOpts(
			WithSupportedEnvVars("NODE_EXTRA_CA_CERTS", "ORG"),
			WithSupportedEnvVarPrefixes("snyk_", "internal_"),
		)

		// setup env var support
		nodeCertsKey := "NODE_EXTRA_CA_CERTS"
		nodeCertsValue := "some/path/to/certs"
		orgKey := "ORG"
		orgValue := "someOrg"

		// setup env var prefix support
		snykKey := "SNYK_TOKEN"
		snykValue := "someSnykToken"
		snykInternalKey := "INTERNAL_SNYK_OAUTH_ENABLED"
		snykInternalValue := "true"

		// a random env var should not be supported
		invalidKey := "NOT_SUPPORTED"
		invalidKeyValue := "thisShouldFail"

		// set all the env vars
		t.Setenv(nodeCertsKey, nodeCertsValue)
		t.Setenv(orgKey, orgValue)
		t.Setenv(snykKey, snykValue)
		t.Setenv(snykInternalKey, snykInternalValue)
		t.Setenv(invalidKey, invalidKeyValue)

		// check they are read correctly
		actualNodeCertsValue := config.GetString(nodeCertsKey)
		assert.Equal(t, nodeCertsValue, actualNodeCertsValue)

		actualOrgValue := config.GetString(orgKey)
		assert.Equal(t, orgValue, actualOrgValue)

		actualSnykKeyValue := config.GetString(snykKey)
		assert.Equal(t, snykValue, actualSnykKeyValue)

		actualSnykInternalValue := config.GetBool(snykInternalKey)
		assert.True(t, actualSnykInternalValue)

		shouldBeNil := config.Get(invalidKey)
		assert.Nil(t, shouldBeNil)

		cleanUpEnvVars()
	})

	t.Run("WithAutomaticEnv takes precedence", func(t *testing.T) {
		config := NewWithOpts(
			WithSupportedEnvVars("NODE_EXTRA_CA_CERTS"),
			WithSupportedEnvVarPrefixes("snyk_", "internal_"),
			WithAutomaticEnv(),
		)

		// setup env var support
		nodeCertsKey := "NODE_EXTRA_CA_CERTS"
		nodeCertsValue := "some/path/to/certs"

		// setup env var prefix support
		snykKey := "SNYK_TOKEN"
		snykValue := "someSnykToken"
		snykInternalKey := "INTERNAL_SNYK_OAUTH_ENABLED"
		snykInternalValue := "true"

		// a random env var would be supported WithAutomatedEnv() enabled
		autoEnv := "AUTOMATIC_ENV"
		autoEnvValue := "thisShouldBeSet"

		// set all the env vars
		t.Setenv(nodeCertsKey, nodeCertsValue)
		t.Setenv(snykKey, snykValue)
		t.Setenv(snykInternalKey, snykInternalValue)
		t.Setenv(autoEnv, autoEnvValue)

		// check they are read correctly
		actualNodeCertsValue := config.GetString(nodeCertsKey)
		assert.Equal(t, nodeCertsValue, actualNodeCertsValue)

		actualSnykKeyValue := config.GetString(snykKey)
		assert.Equal(t, snykValue, actualSnykKeyValue)

		actualSnykInternalValue := config.GetBool(snykInternalKey)
		assert.True(t, actualSnykInternalValue)

		actualAutoEnvValue := config.Get(autoEnv)
		assert.Equal(t, autoEnvValue, actualAutoEnvValue)

		cleanUpEnvVars()
	})
}

func Test_Configuration_caching_enabled(t *testing.T) {
	myKey := "some"
	myValue := 42
	defaultFuncCalled := 0
	cacheDuration := 10 * time.Minute

	config := NewWithOpts(WithCachingEnabled(cacheDuration))
	config.AddDefaultValue(myKey, func(existingValue interface{}) (interface{}, error) {
		defaultFuncCalled++

		if existingValue != nil {
			return existingValue, nil
		}

		return defaultFuncCalled, nil
	})

	// get uncached value
	actual1 := config.GetInt(myKey)
	assert.Equal(t, defaultFuncCalled, actual1)

	// get cached value
	defaultFuncCalledBefore := defaultFuncCalled
	actual2 := config.GetInt(myKey)
	assert.Equal(t, defaultFuncCalledBefore, defaultFuncCalled, "Default function should not be called when using cached value")
	assert.Equal(t, actual1, actual2)

	// set explicit value and invalidate cache
	config.Set(myKey, myValue)
	actual3 := config.GetInt(myKey)
	assert.Equal(t, defaultFuncCalledBefore+1, defaultFuncCalled)
	assert.Equal(t, myValue, actual3)

	// get cached value
	defaultFuncCalledBefore = defaultFuncCalled
	actual4 := config.GetInt(myKey)
	assert.Equal(t, myValue, actual4)
	assert.Equal(t, defaultFuncCalledBefore, defaultFuncCalled, "Default function should not be called when using cached value")

	// create a clone and ensure to still access the cached values
	clonedConfig := config.Clone()
	actual4Cloned := clonedConfig.GetInt(myKey)
	assert.Equal(t, myValue, actual4Cloned)
	assert.Equal(t, defaultFuncCalledBefore, defaultFuncCalled, "Default function should not be called when using cached value")

	// clear cache
	clonedConfig.ClearCache()

	actual5Cloned := clonedConfig.GetInt(myKey)
	assert.Equal(t, myValue, actual5Cloned)
	assert.Equal(t, defaultFuncCalledBefore+1, defaultFuncCalled, "Default function should be called after clearing the cache")
}

func Test_extendedViper_cacheSettings(t *testing.T) {
	cacheDuration := 10 * time.Minute

	config := NewWithOpts(WithCachingEnabled(cacheDuration))
	assert.False(t, config.GetBool(CONFIG_CACHE_DISABLED))
	assert.Equal(t, cacheDuration, config.GetDuration(CONFIG_CACHE_TTL))

	ev, ok := config.(*extendedViper)
	assert.True(t, ok)
	enabled, duration, err := ev.getCacheSettings()
	assert.NoError(t, err)
	assert.True(t, enabled)
	assert.Equal(t, cacheDuration, duration)
}

func Test_toDuration(t *testing.T) {
	testcases := []struct {
		name     string
		input    interface{}
		expected time.Duration
	}{
		{
			name:     "string",
			input:    "10s",
			expected: 10 * time.Second,
		},
		{
			name:     "duration",
			input:    10 * time.Minute,
			expected: 10 * time.Minute,
		},
		{
			name:     "int",
			input:    10,
			expected: 10 * time.Nanosecond,
		},
		{
			name:     "int64",
			input:    int64(10000),
			expected: 10000 * time.Nanosecond,
		},
	}

	for _, tcase := range testcases {
		t.Run(tcase.name, func(t *testing.T) {
			actual, err := toDuration(tcase.input)
			assert.NoError(t, err)
			assert.Equal(t, actual, tcase.expected)
		})
	}
}
