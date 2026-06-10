package workflow

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewDataFromInput(t *testing.T) {
	expectedContentType := "application/json"
	expectedContentType2 := "application/binary"
	expectedContentLocation := "/folder/of/source/file.json"

	input := NewData(NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata"), expectedContentType, []byte{})
	input.SetContentLocation(expectedContentLocation)
	input.AddError(snyk_errors.Error{
		Title:          "Generic but helpful error message",
		Classification: "ACTIONABLE",
		Level:          "warning",
		Detail:         "Error code detail",
		Links:          []string{"https://docs.snyk.io/\n"},
	})

	output := NewDataFromInput(input, NewTypeIdentifier(NewWorkflowIdentifier("yourcommand"), "yourdata"), expectedContentType2, []byte{})

	actualContentLocation := output.GetContentLocation()
	assert.Equal(t, expectedContentLocation, actualContentLocation)

	actualContentLocation = input.GetContentLocation()
	assert.Equal(t, expectedContentLocation, actualContentLocation)

	expectedFragment := input.GetIdentifier().Fragment
	actualFragment := output.GetIdentifier().Fragment
	assert.Equal(t, expectedFragment, actualFragment)

	assert.Equal(t, expectedContentType, input.GetContentType())
	assert.Equal(t, expectedContentType2, output.GetContentType())
	assert.Equal(t, input.GetErrorList(), output.GetErrorList())

	fmt.Println(input)
	fmt.Println(output)
}

func Test_DataImpl_SetPayload_GetPayload(t *testing.T) {
	t.Run("in-memory payload round-trip", func(t *testing.T) {
		expectedConfig := configuration.NewInMemory()
		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, -1)
		logger := zerolog.Nop()

		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "dtype")
		data := NewData(id, "text/plain", []byte("initial"),
			WithConfiguration(expectedConfig), WithLogger(&logger))

		// SetPayload replaces the payload
		data.SetPayload([]byte("updated"))
		result := data.GetPayload()
		assert.Equal(t, []byte("updated"), result)
	})

	t.Run("on-disk payload via GetPayload", func(t *testing.T) {
		tmpDir := t.TempDir()
		expectedConfig := configuration.NewInMemory()
		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, 0)
		expectedConfig.Set(configuration.TEMP_DIR_PATH, tmpDir)
		logger := zerolog.Nop()

		payloadBytes := []byte("data that goes to disk")
		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "disktype")
		data := NewData(id, "application/octet-stream", payloadBytes,
			WithConfiguration(expectedConfig), WithLogger(&logger))

		// in-memory payload should have been nil'd out
		rawPayload := reflect.ValueOf(data).Elem().FieldByName("payload")
		assert.True(t, rawPayload.IsNil())

		// GetPayload reads from disk
		result := data.GetPayload()
		assert.Equal(t, payloadBytes, result)
	})

	t.Run("GetPayload from missing file returns nil", func(t *testing.T) {
		tmpDir := t.TempDir()
		expectedConfig := configuration.NewInMemory()
		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, 0)
		expectedConfig.Set(configuration.TEMP_DIR_PATH, tmpDir)
		logger := zerolog.Nop()

		payloadBytes := []byte("will be on disk")
		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "missingfile")
		data := NewData(id, "application/octet-stream", payloadBytes,
			WithConfiguration(expectedConfig), WithLogger(&logger))

		// Delete the file on disk to simulate missing file
		loc := reflect.ValueOf(data).Elem().FieldByName("payloadLocation").FieldByName("Path")
		err := os.Remove(loc.String())
		assert.NoError(t, err)

		result := data.GetPayload()
		assert.Nil(t, result)
	})
}

func Test_NewData(t *testing.T) {
	t.Run("with options", func(t *testing.T) {
		expectedConfig := configuration.NewInMemory()
		expectedConfig.Set("IN_MEMORY_THRESHOLD_BYTES", 10)
		expectedLogger := zerolog.Logger{}
		expectedContentType := "application/json"

		input := NewData(
			NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata"),
			expectedContentType,
			[]byte{},
			WithConfiguration(expectedConfig),
			WithLogger(&expectedLogger))
		// TODO: assert that the config options were applied
		actualIdentifier := input.GetIdentifier()
		assert.Equal(t, "did", actualIdentifier.Scheme)
	})

	t.Run("with writing to disk disabled", func(t *testing.T) {
		expectedConfig := configuration.NewInMemory()
		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, -1)
		expectedLogger := zerolog.Logger{}
		expectedContentType := "application/json"

		expectedIdentifier := NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata")
		data := NewData(
			expectedIdentifier,
			expectedContentType,
			[]byte("put some data in here so that it is bigger than the expectedThreshold"),
			WithConfiguration(expectedConfig),
			WithLogger(&expectedLogger),
			WithInputData(nil))

		actualPayloadLocation := reflect.ValueOf(data).Elem().FieldByName("payloadLocation").FieldByName("Type")
		assert.Equal(t, int64(InMemory), actualPayloadLocation.Int())

		actualPayloadLocationPath := reflect.ValueOf(data).Elem().FieldByName("payloadLocation").FieldByName("Path")
		assert.Equal(t, "", actualPayloadLocationPath.String())
	})

	t.Run("with user provided temp directory and threshold", func(t *testing.T) {
		expectedConfig := configuration.NewInMemory()
		expectedLogger := zerolog.Logger{}
		expectedContentType := "application/json"

		expectedTempDir := path.Join(os.TempDir(), "dataImpl_test")
		err := os.Mkdir(expectedTempDir, 0755)

		// cleanup temp dir and files
		defer func(path string) {
			err = os.RemoveAll(path)
			if err != nil {
				fmt.Println("failed to remove temp dir: ", err)
			}
		}(expectedTempDir)

		assert.NoError(t, err)

		expectedConfig.Set(configuration.TEMP_DIR_PATH, expectedTempDir)

		expectedThreshold := 0
		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, expectedThreshold)

		expectedIdentifier := NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata")

		NewData(
			expectedIdentifier,
			expectedContentType,
			[]byte("put some data in here so that it is bigger than the expectedThreshold"),
			WithConfiguration(expectedConfig),
			WithLogger(&expectedLogger),
			WithInputData(nil))

		//	 assert that /tmp directory exists
		info, err := os.Stat(expectedTempDir)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())

		expectedFileName := "workflow.mydata."

		actualFiles, err := os.ReadDir(expectedTempDir)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(actualFiles))
		assert.Contains(t, actualFiles[0].Name(), expectedFileName)
	})

	t.Run("applyConfiguration relocates in-memory payload to disk", func(t *testing.T) {
		tmpDir := t.TempDir()
		logger := zerolog.Nop()

		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "applytest")
		payloadBytes := []byte("payload that should end up on disk after applyConfiguration")

		data := NewData(id, "application/octet-stream", payloadBytes, WithLogger(&logger))

		// Without WithConfiguration, payload stays in memory (threshold defaults to -1)
		di, ok := data.(*DataImpl)
		require.True(t, ok)
		assert.Equal(t, InMemory, di.payloadLocation.Type)
		assert.NotNil(t, di.payload)

		// Now apply a configuration with threshold=0 — everything spills to disk
		cfg := configuration.NewInMemory()
		cfg.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, 0)
		cfg.Set(configuration.TEMP_DIR_PATH, tmpDir)
		di.applyConfiguration(cfg)

		assert.Equal(t, OnDisk, di.payloadLocation.Type)
		assert.Nil(t, di.payload)
		assert.Contains(t, di.payloadLocation.Path, tmpDir)

		// GetPayload still returns the original bytes
		result := data.GetPayload()
		assert.Equal(t, payloadBytes, result)
	})

	t.Run("applyConfiguration is no-op when threshold is disabled", func(t *testing.T) {
		logger := zerolog.Nop()
		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "noop")
		payloadBytes := []byte("stays in memory")

		data := NewData(id, "text/plain", payloadBytes, WithLogger(&logger))
		di, ok := data.(*DataImpl)
		require.True(t, ok)

		cfg := configuration.NewInMemory()
		cfg.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, -1)
		di.applyConfiguration(cfg)

		assert.Equal(t, InMemory, di.payloadLocation.Type)
		assert.NotNil(t, di.payload)
	})

	t.Run("applyConfiguration is no-op when threshold key is not set in config", func(t *testing.T) {
		logger := zerolog.Nop()
		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "unset")
		payloadBytes := []byte("should stay in memory because key is unset")

		data := NewData(id, "text/plain", payloadBytes, WithLogger(&logger))
		di, ok := data.(*DataImpl)
		require.True(t, ok)
		assert.Equal(t, -1, di.inMemoryThreshold)

		cfg := configuration.NewInMemory()
		require.Nil(t, cfg.Get(configuration.IN_MEMORY_THRESHOLD_BYTES))
		di.applyConfiguration(cfg)

		assert.Equal(t, -1, di.inMemoryThreshold)
		assert.Equal(t, InMemory, di.payloadLocation.Type)
		assert.NotNil(t, di.payload)
	})

	t.Run("applyConfiguration uses AddDefaultValue when key is not Set", func(t *testing.T) {
		tmpDir := t.TempDir()
		logger := zerolog.Nop()
		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "adddefault")
		payloadBytes := []byte("spill via default value functions")

		data := NewData(id, "application/octet-stream", payloadBytes, WithLogger(&logger))
		di, ok := data.(*DataImpl)
		require.True(t, ok)

		cfg := configuration.NewInMemory()
		cfg.AddDefaultValue(configuration.IN_MEMORY_THRESHOLD_BYTES, configuration.StandardDefaultValueFunction(0))
		cfg.AddDefaultValue(configuration.TEMP_DIR_PATH, configuration.StandardDefaultValueFunction(tmpDir))

		assert.False(t, cfg.IsSet(configuration.IN_MEMORY_THRESHOLD_BYTES))
		assert.False(t, cfg.IsSet(configuration.TEMP_DIR_PATH))
		require.NotNil(t, cfg.Get(configuration.IN_MEMORY_THRESHOLD_BYTES))
		require.NotNil(t, cfg.Get(configuration.TEMP_DIR_PATH))

		di.applyConfiguration(cfg)

		assert.Equal(t, OnDisk, di.payloadLocation.Type)
		assert.Nil(t, di.payload)
		assert.Contains(t, di.payloadLocation.Path, tmpDir)
	})

	t.Run("applyConfiguration with threshold only uses system temp when TEMP_DIR_PATH absent", func(t *testing.T) {
		logger := zerolog.Nop()
		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "notemp")
		payloadBytes := []byte("spill with no temp path in config")

		data := NewData(id, "application/octet-stream", payloadBytes, WithLogger(&logger))
		di, ok := data.(*DataImpl)
		require.True(t, ok)

		cfg := configuration.NewInMemory()
		cfg.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, 0)
		require.Nil(t, cfg.Get(configuration.TEMP_DIR_PATH))

		di.applyConfiguration(cfg)

		assert.Equal(t, OnDisk, di.payloadLocation.Type)
		assert.Contains(t, di.payloadLocation.Path, os.TempDir())
	})

	t.Run("applyConfiguration is no-op when payload is already on disk", func(t *testing.T) {
		tmpDir := t.TempDir()
		logger := zerolog.Nop()

		cfg := configuration.NewInMemory()
		cfg.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, 0)
		cfg.Set(configuration.TEMP_DIR_PATH, tmpDir)

		id := NewTypeIdentifier(NewWorkflowIdentifier("cmd"), "alreadyondisk")
		payloadBytes := []byte("on disk from the start")

		data := NewData(id, "application/octet-stream", payloadBytes, WithConfiguration(cfg), WithLogger(&logger))
		di, ok := data.(*DataImpl)
		require.True(t, ok)
		assert.Equal(t, OnDisk, di.payloadLocation.Type)
		originalPath := di.payloadLocation.Path

		// applyConfiguration again should not relocate
		di.applyConfiguration(cfg)
		assert.Equal(t, OnDisk, di.payloadLocation.Type)
		assert.Equal(t, originalPath, di.payloadLocation.Path)
	})

	t.Run("when configuration is not provided, filesystem cache is not used", func(t *testing.T) {
		expectedConfig := configuration.NewInMemory()
		expectedLogger := zerolog.Logger{}
		expectedContentType := "application/json"

		expectedTempDir := path.Join(os.TempDir(), "dataImpl_test")
		err := os.Mkdir(expectedTempDir, 0755)

		// cleanup temp dir and files
		defer func(path string) {
			err = os.RemoveAll(path)
			if err != nil {
				fmt.Println("failed to remove temp dir: ", err)
			}
		}(expectedTempDir)
		assert.NoError(t, err)

		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, 1)
		expectedConfig.Set(configuration.TEMP_DIR_PATH, expectedTempDir)
		expectedIdentifier := NewTypeIdentifier(NewWorkflowIdentifier("mycommand"), "mydata")

		dataWithConfig := NewData(
			expectedIdentifier,
			expectedContentType,
			[]byte("put some data in here so that it is bigger than the expectedThreshold"),
			WithConfiguration(expectedConfig),
			WithLogger(&expectedLogger),
			WithInputData(nil))

		// assert that payload location is on disk
		actualPayloadLocationWithConfig := reflect.ValueOf(dataWithConfig).Elem().FieldByName("payloadLocation").FieldByName("Type")
		assert.Equal(t, int64(OnDisk), actualPayloadLocationWithConfig.Int())

		// assert that payload location path is empty
		actualPayloadLocationPathWithConfig := reflect.ValueOf(dataWithConfig).Elem().FieldByName("payloadLocation").FieldByName("Path")
		assert.Contains(t, actualPayloadLocationPathWithConfig.String(), expectedTempDir)

		dataNoConfig := NewData(
			expectedIdentifier,
			expectedContentType,
			[]byte("put some data in here so that it is bigger than the expectedThreshold"),
			WithLogger(&expectedLogger),
			WithInputData(nil))

		// assert that payload location is in memory
		actualPayloadLocationNoConfig := reflect.ValueOf(dataNoConfig).Elem().FieldByName("payloadLocation").FieldByName("Type")
		assert.Equal(t, int64(InMemory), actualPayloadLocationNoConfig.Int())

		// assert that payload location path is empty
		actualPayloadLocationPathNoConfig := reflect.ValueOf(dataNoConfig).Elem().FieldByName("payloadLocation").FieldByName("Path")
		assert.Equal(t, "", actualPayloadLocationPathNoConfig.String())
	})
}
