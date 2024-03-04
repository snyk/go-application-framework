package configuration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

const key = "someKey"
const expectedValue = "someValue"

func Test_JsonStorage_Set_NoConfigFile(t *testing.T) {
	// Arrange
	t.Parallel()
	testCases := []struct {
		setup           string
		customSetupFunc func(t *testing.T) string
	}{
		{
			setup: "File does not exist",
			customSetupFunc: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "test.json")
			},
		},
		{
			setup: "Leading folders to the file do not exist",
			customSetupFunc: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "nonexistent", "test.json")
			},
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.setup+" - config file is created", func(t *testing.T) {
			t.Parallel()
			configFile := testCase.customSetupFunc(t)
			storage := configuration.NewJsonStorage(configFile)

			// Act
			err := storage.Set(key, expectedValue)

			// Assert
			assert.Nil(t, err)
			storedConfig := readStoredConfigFile(t, configFile)
			assertConfigContainsKey(t, storedConfig, key, expectedValue)
		})
	}
}

func Test_JsonStorage_Set_ConfigFileHasValues(t *testing.T) {
	// Arrange
	t.Parallel()
	const preExistingKey = "someOtherKey"
	const preExistingValue = "someOtherValue"

	preExistingConfig := map[string]string{
		preExistingKey: preExistingValue,
	}

	unknownJson, _ := json.Marshal(preExistingConfig)
	configFile := filepath.Join(t.TempDir(), "test.json")
	err := os.WriteFile(configFile, unknownJson, 0666)
	assert.Nil(t, err)
	storage := configuration.NewJsonStorage(configFile)

	// Act
	err = storage.Set(key, expectedValue)
	assert.Nil(t, err)

	// Assert
	storedConfig := readStoredConfigFile(t, configFile)
	t.Run("File contains key", func(t *testing.T) {
		t.Parallel()
		assertConfigContainsKey(t, storedConfig, key, expectedValue)
	})
	t.Run("Pre-stored values are not deleted", func(t *testing.T) {
		t.Parallel()
		assertConfigContainsKey(t, storedConfig, preExistingKey, preExistingValue)
	})
	assertSetCallDoesNotDeleteOtherValues(t, storage, configFile, expectedValue, key)
	t.Run("Overwrites existing value", func(t *testing.T) {
		t.Parallel()
		const newValue = "new value"
		assert.Contains(t, storedConfig, key)
		err = storage.Set(key, newValue)
		assert.Nil(t, err)
		storedConfig = readStoredConfigFile(t, configFile)
		assert.Nil(t, err)
		assert.Equal(t, newValue, storedConfig[key])
	})
}

func Test_JsonStorage_Set_BrokenConfigFile(t *testing.T) {
	// Arrange
	t.Parallel()
	brokenJson := []byte("this }}is not j[]son")
	storage := storageWithTempConfigFile(t, brokenJson)

	// Act
	err := storage.Set(key, expectedValue)

	// Assert
	t.Run("Returns an error", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, err)
	})
}

func Test_JsonStorage_Set_InvalidValue(t *testing.T) {
	// Arrange
	t.Parallel()
	storage := storageWithTempConfigFile(t, []byte("{}"))
	invalidValue := make(chan int) // invalid because channels are not JSON serializable

	// Act
	err := storage.Set(key, invalidValue)

	// Assert
	t.Run("Returns an error", func(t *testing.T) {
		t.Parallel()
		assert.NotNil(t, err)
	})
}

func storageWithTempConfigFile(t *testing.T, jsonBytes []byte) *configuration.JsonStorage {
	t.Helper()
	configFile := filepath.Join(t.TempDir(), "test.json")
	err := os.WriteFile(configFile, jsonBytes, 0666)
	assert.Nil(t, err)

	return configuration.NewJsonStorage(configFile)
}

func readStoredConfigFile(t *testing.T, configFile string) map[string]any {
	t.Helper()

	storedConfig := make(map[string]any)
	fileBytes, err := os.ReadFile(configFile)
	assert.Nil(t, err)
	err = json.Unmarshal(fileBytes, &storedConfig)
	assert.Nil(t, err)

	return storedConfig
}

func assertSetCallDoesNotDeleteOtherValues(
	t *testing.T,
	storage *configuration.JsonStorage,
	configFile string,
	preExistingValue string,
	preExistingValueKey string,
) bool {
	t.Helper()
	return t.Run("A second call to Set does not delete the first value", func(t *testing.T) {
		storedConfig := readStoredConfigFile(t, configFile)
		assert.Equal(t, preExistingValue, storedConfig[preExistingValueKey])

		err := storage.Set("SomeWildKey", "SomeWildValue")

		assert.Nil(t, err)
		storedConfig = readStoredConfigFile(t, configFile)
		assert.Equal(t, preExistingValue, storedConfig[preExistingValueKey])
	})
}

func assertConfigContainsKey(
	t *testing.T,
	storedConfig map[string]any,
	expectedValueKey string,
	expectedValue string,
) {
	t.Helper()
	assert.Equal(t, expectedValue, storedConfig[expectedValueKey])
}
