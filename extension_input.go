package cli_extension_lib_go

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
)

type ExtensionInput struct {
	Debug   bool                   `json:"debug"`
	Token   string                 `json:"token,omitempty"`
	Command *ExtensionInputCommand `json:"command"`
}

type ExtensionInputCommand struct {
	// analogous to Command in ExtensionMetadata
	Name        string                 `json:"name"`
	Subcommand  *ExtensionInputCommand `json:"subcommand"`
	Options     map[string]any         `json:"options"`
	Positionals []string               `json:"positionals"`
}

func DeserExtensionInput(inputString string) (*ExtensionInput, error) {
	var extensionInput ExtensionInput
	err := json.Unmarshal([]byte(inputString), &extensionInput)
	if err != nil {
		return nil, err
	}

	if extensionInput.Command == nil {
		return &extensionInput, fmt.Errorf("`Command` field in extension input cannot be nil")
	}

	return &extensionInput, nil
}

func OptionValue[T any](c *ExtensionInputCommand, name string) (T, error) {
	v, exists := c.Options[name]
	var typedValue T
	if !exists {
		return typedValue, fmt.Errorf("option %s not found in command", name)
	}
	typedValue, ok := v.(T)
	if !ok {
		typeStr := reflect.ValueOf(typedValue).String()
		return typedValue, fmt.Errorf("cannot convert option value to %s", typeStr)
	}
	return typedValue, nil
}

func (c *ExtensionInputCommand) StringOptionValue(name string) (string, error) {
	return OptionValue[string](c, name)
}

func (c *ExtensionInputCommand) BoolOptionValue(name string) (bool, error) {
	return OptionValue[bool](c, name)
}

func (i *ExtensionInput) GetHttpTransport() (*http.Transport, error) {
	certificateLocation, _ := os.LookupEnv("NODE_EXTRA_CA_CERTS")

	certPEMBlock, err := ioutil.ReadFile(certificateLocation)
	if err != nil {
		return nil, err
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if !pool.AppendCertsFromPEM(certPEMBlock) {
		return nil, fmt.Errorf("Failed to add certificate! %s", certificateLocation)
	}

	tls := &tls.Config{
		RootCAs: pool,
	}

	return &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tls,
	}, nil
}
