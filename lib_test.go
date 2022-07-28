package cli_extension_lib_go_test

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
	"testing"

	cli_extension_lib_go "github.com/snyk/cli-extension-lib-go"
	extension "github.com/snyk/cli-extension-lib-go/extension"

	"github.com/stretchr/testify/assert"
)

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
	buffer := bytes.NewBuffer([]byte(`{"debug":true,"proxy_port":8080,"command":{"name":"woof","subcommand":null,"options":{"lang":"foolang"},"positionals":[]}}`))
	inputStr, err := cli_extension_lib_go.ReadInput(buffer)
	assert.Equal(t, `{"debug":true,"proxy_port":8080,"command":{"name":"woof","subcommand":null,"options":{"lang":"foolang"},"positionals":[]}}`, inputStr)
	assert.Nil(t, err)

	extensionInput, err := cli_extension_lib_go.DeserExtensionInput(inputStr)
	assert.Nil(t, err)
	assert.Equal(t, true, extensionInput.Debug)
	assert.Equal(t, 8080, extensionInput.ProxyPort)
	assert.Equal(t, "woof", extensionInput.Command.Name)
	assert.Nil(t, extensionInput.Command.Subcommand)
	assert.Equal(t, "foolang", extensionInput.Command.Options["lang"])

	lang, err := extensionInput.Command.StringOptionValue("lang")
	assert.Nil(t, err)
	assert.Equal(t, "foolang", lang)
}

func Test_canDeserializeExtensionMetadataFile(t *testing.T) {
	ext, err := extension.TryLoad("test/fixtures/sclix_woof")
	assert.Nil(t, err)
	assert.Equal(t, "test/fixtures/sclix_woof", ext.Root)
	assert.Equal(t, "test/fixtures/sclix_woof/sclix_woof"+fmt.Sprintf("_%s_%s", runtime.GOOS, runtime.GOARCH), ext.BinPath)
	assert.Equal(t, "sclix_woof", ext.Metadata.Name)
	assert.Equal(t, "woof", ext.Metadata.Command.Name)
	assert.Nil(t, ext.Metadata.Command.Subcommands)
	assert.Equal(t, "0.1.0", ext.Metadata.Version)
	assert.Equal(t, "patch ascii art", ext.Metadata.Description)

	assert.Equal(t, 1, len(ext.Metadata.Command.Options))
	assert.Equal(t, "lang", ext.Metadata.Command.Options[0].Name)
	assert.Equal(t, "l", ext.Metadata.Command.Options[0].Shorthand)
	assert.Equal(t, "string", ext.Metadata.Command.Options[0].Type)
	assert.Equal(t, "default-lang", ext.Metadata.Command.Options[0].Default)
	assert.Equal(t, "the language you want to woof in", ext.Metadata.Command.Options[0].Description)
}

// A more complex extension.json that has subcommands
// Also, tests the InitExtensionWithArgs and the convenience methods for getting option values
func Test_extWithSubcommandsAndUsingInitExtension(t *testing.T) {
	// this is what the CLI should launch the extension with
	buffer := bytes.NewBuffer([]byte(`{"debug":true,"proxy_port":8080,"command":{"name":"depgraph","subcommand":{"name": "test", "options":{"output":"json","detailed":false},"positionals":["/path/to/test"]}}}`))

	ext, extInput, err := cli_extension_lib_go.InitExtensionWithArgs("test/fixtures/sclix_dg", buffer)
	fmt.Println(extInput)

	assert.NotNil(t, ext)
	assert.NotNil(t, extInput)
	assert.Nil(t, err)

	assert.Equal(t, "depgraph", ext.Metadata.Command.Name)
	assert.Equal(t, "test/fixtures/sclix_dg/sclix_dg"+fmt.Sprintf("_%s_%s", runtime.GOOS, runtime.GOARCH), ext.BinPath)

	assert.NotNil(t, extInput.Command.Subcommand)
	assert.Equal(t, "test", extInput.Command.Subcommand.Name)

	output, err := extInput.Command.Subcommand.StringOptionValue("output")
	assert.Nil(t, err)
	assert.Equal(t, "json", output)

	detailed, err := extInput.Command.Subcommand.BoolOptionValue("detailed")
	assert.Nil(t, err)
	assert.Equal(t, false, detailed)
}
