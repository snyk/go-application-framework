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

func Test_NewData(t *testing.T) {
	expectedConfig := configuration.NewInMemory()
	expectedConfig.Set("IN_MEMORY_THRESHOLD_BYTES", 10)
	expectedLogger := zerolog.Logger{}
	expectedContentType := "application/json"

	t.Run("with options", func(t *testing.T) {
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
		expectedConfig.Set(configuration.IN_MEMORY_THRESHOLD_BYTES, -1)
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
}
