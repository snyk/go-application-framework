package cli_extension_lib_go_test

import (
	"bytes"
	"fmt"
	"github.com/snyk/cli-extension-lib-go"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

type WoofInput struct {
	Lang string `json:"lang"`
}

func Test_ParseInput(t *testing.T) {
	inputStr := `{"debug":true,"proxyPort":8080,"args":{"lang":"foolang"}}`
	extensionInput, err := cli_extension_lib_go.ParseInput[WoofInput](inputStr)
	assert.Nil(t, err)
	assert.Equal(t, true, extensionInput.Debug)
	assert.Equal(t, 8080, extensionInput.ProxyPort)
	assert.Equal(t, "foolang", extensionInput.Args.Lang)
}

func Test_ReadInput_worksNormally(t *testing.T) {
	buffer := bytes.NewBuffer([]byte("hello\n\n"))
	inputStr, err := cli_extension_lib_go.ReadInput(buffer)
	assert.Nil(t, err)
	assert.Equal(t, "hello", inputStr)
}

// verify that ReadInput returns even without the double newline if it gets an EOF
func Test_ReadInput_returnsOnEOFEvenWithoutDoulbeNewline(t *testing.T) {
	buffer := bytes.NewBuffer([]byte("hello\n")) // note: only a single newline
	inputStr, err := cli_extension_lib_go.ReadInput(buffer)
	assert.Nil(t, err)
	log.Println(inputStr)
	assert.Equal(t, "hello", inputStr)
}

type MockRuneReader struct {
}

func (m *MockRuneReader) ReadRune() (rune, int, error) {
	err := fmt.Errorf("some error")
	return 0, 0, err
}

// Verify that ReadInput returns an error if one is generated that is not EOF
func Test_ReadInput_returnsIOError(t *testing.T) {
	reader := &MockRuneReader{}
	_, err := cli_extension_lib_go.ReadInput(reader)
	assert.NotNil(t, err)
	assert.Equal(t, "some error", err.Error())
}

// Verifies the full flow of reading input and parsing it
func Test_readAndParseInput(t *testing.T) {
	buffer := bytes.NewBuffer([]byte("{\"debug\":true,\"proxyPort\":8080,\"args\":{\"lang\":\"foolang\"}}\n\n"))
	inputStr, err := cli_extension_lib_go.ReadInput(buffer)
	assert.Equal(t, `{"debug":true,"proxyPort":8080,"args":{"lang":"foolang"}}`, inputStr)
	assert.Nil(t, err)
	extensionInput, err := cli_extension_lib_go.ParseInput[WoofInput](inputStr)
	assert.Nil(t, err)
	assert.Equal(t, true, extensionInput.Debug)
	assert.Equal(t, 8080, extensionInput.ProxyPort)
	assert.Equal(t, "foolang", extensionInput.Args.Lang)
}

func Test_canDeserializeExtensionMetadataFile(t *testing.T) {
	x, err := cli_extension_lib_go.DeserExtensionMetadata("test/fixtures/canDeserializeExtensionMetadataFile/extension.json")
	assert.Nil(t, err)
	assert.Equal(t, "sclix-woof", x.Name)
	assert.Equal(t, "woof", x.Command)
	assert.Equal(t, "0.1.0", x.Version)
	assert.Equal(t, "patch ascii art", x.Description)
	assert.Equal(t, 1, len(x.Options))
	assert.Equal(t, "lang", x.Options[0].Name)
	assert.Equal(t, "l", x.Options[0].Shorthand)
	assert.Equal(t, "string", x.Options[0].Type)
	assert.Equal(t, "en", x.Options[0].Default)
	assert.Equal(t, "the language you want to show", x.Options[0].Description)
}

func Test_canDeserializeExtensionMetadataFileAndDefaultDefaultsAreCorrect(t *testing.T) {
	x, err := cli_extension_lib_go.DeserExtensionMetadata("test/fixtures/canDeserializeExtensionMetadataFile/extension.json")
	assert.Nil(t, err)
	assert.Equal(t, "sclix-woof", x.Name)
	assert.Equal(t, "woof", x.Command)
	assert.Equal(t, "0.1.0", x.Version)
	assert.Equal(t, "patch ascii art", x.Description)
	assert.Equal(t, 1, len(x.Options))
	assert.Equal(t, "lang", x.Options[0].Name)
	assert.Equal(t, "l", x.Options[0].Shorthand)
	assert.Equal(t, "string", x.Options[0].Type)
	assert.Equal(t, "en", x.Options[0].Default)
	assert.Equal(t, "the language you want to show", x.Options[0].Description)
}
