package configuration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	dummyFile := bytes.Buffer{}
	unknownJson, _ := json.Marshal(preExistingConfig)
	dummyFile.Write(unknownJson)
	storage := NewJsonStorage(&dummyFile)

	// Act
	err := storage.Set(key, expectedValue)

	// Assert
	storedConfig := make(map[string]any)
	_ = json.Unmarshal(dummyFile.Bytes(), &storedConfig)

	t.Run("No error", func(t *testing.T) {
		assert.Nil(t, err)
	})
	t.Run("File contains key", func(t *testing.T) {
		assert.Equal(t, expectedValue, storedConfig[key])
	})
	t.Run("Pre-stored values are not deleted", func(t *testing.T) {
		assert.Equal(t, preExistingConfig[preExistingKey], storedConfig[preExistingKey])
	})
	t.Run("A second call to Set does not delete the first value", func(t *testing.T) {
		err = storage.Set("SomeWildKey", "SomeWildValue")
		_ = json.Unmarshal(dummyFile.Bytes(), &storedConfig)
		assert.Nil(t, err)
		assert.Equal(t, expectedValue, storedConfig[key])
	})
	t.Run("Overwrites existing value", func(t *testing.T) {
		const newValue = "new value"
		err = storage.Set(key, newValue)
		_ = json.Unmarshal(dummyFile.Bytes(), &storedConfig)
		assert.Nil(t, err)
		assert.Equal(t, newValue, storedConfig[key])
	})
}
