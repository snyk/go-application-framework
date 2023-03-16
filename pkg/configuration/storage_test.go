package configuration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_JsonStorage_NoConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	nonExistingFile := filepath.Join(tempDir, "nonExistingFile.json")
	storage := NewJsonStorage(nonExistingFile)

	err := storage.Set("someKey", "someValue")
	assert.Nil(t, err)
}

func Test_JsonStorage_Set(t *testing.T) {
	// Arrange
	t.Parallel()
	const key = "someKey"
	const expectedValue = "someValue"
	const preExistingKey = "someOtherKey"
	const preExistingValue = "someOtherValue"

	preExistingConfig := map[string]string{
		preExistingKey: preExistingValue,
	}

	unknownJson, _ := json.Marshal(preExistingConfig)
	// filepath.Join()
	configFile := filepath.Join(t.TempDir(), "test.json")
	err := os.WriteFile(configFile, unknownJson, 0666)
	assert.Nil(t, err)
	storage := NewJsonStorage(configFile)

	// Act
	err = storage.Set(key, expectedValue)
	assert.Nil(t, err)

	// Assert
	storedConfig := make(map[string]any)
	fileBytes, err := os.ReadFile(configFile)
	assert.Nil(t, err)
	err = json.Unmarshal(fileBytes, &storedConfig)
	assert.Nil(t, err)

	t.Run("File contains key", func(t *testing.T) {
		assert.Equal(t, expectedValue, storedConfig[key])
	})
	t.Run("Pre-stored values are not deleted", func(t *testing.T) {
		assert.Equal(t, preExistingConfig[preExistingKey], storedConfig[preExistingKey])
	})
	t.Run("A second call to Set does not delete the first value", func(t *testing.T) {
		err = storage.Set("SomeWildKey", "SomeWildValue")
		assert.Nil(t, err)
		fileContent, _ := os.ReadFile(configFile)
		_ = json.Unmarshal(fileContent, &storedConfig)
		assert.Nil(t, err)
		assert.Equal(t, expectedValue, storedConfig[key])
	})
	t.Run("Overwrites existing value", func(t *testing.T) {
		const newValue = "new value"

		fileContent, err := os.ReadFile(configFile)
		err = storage.Set(key, newValue)
		assert.Nil(t, err)
		fileContent, err = os.ReadFile(configFile)
		_ = json.Unmarshal(fileContent, &storedConfig)
		assert.Nil(t, err)
		assert.Equal(t, newValue, storedConfig[key])
	})
}
