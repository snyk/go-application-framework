package cli_extension_lib_go

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

type ExtensionMetadata struct {
	Name        string   `json:"name"`
	Command     string   `json:"command"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Options     []Option `json:"options"`
}

type Option struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Shorthand   string `json:"shorthand"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

type ExtensionInput[T any] struct {
	// Standard stuff do we want to passed to all extensions
	Debug     bool `json:"debug"`
	ProxyPort int  `json:"proxyPort"`

	// Extension-specific args
	Args T `json:"args"`
}

func ReadInput(reader io.RuneReader) (string, error) {
	consecutiveNewlinesCount := 0
	chars := []rune{}

	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			if err.Error() == "EOF" {
				// normal EOF so don't propagate the error
				break
			} else {
				// some other error so propagate it
				return "", err
			}
		}
		if char == '\n' {
			consecutiveNewlinesCount++
		} else {
			consecutiveNewlinesCount = 0
			chars = append(chars, char)
		}

		if consecutiveNewlinesCount == 2 {
			break
		}
	}

	inputString := string(chars)
	return inputString, nil
}

func ParseInput[T any](inputString string) (*ExtensionInput[T], error) {
	rawBytes := []byte(inputString)

	var input ExtensionInput[T]
	err := json.Unmarshal(rawBytes, &input)
	if err != nil {
		return nil, err
	}

	return &input, nil
}

func GetDebugLogger(debug bool, extensionName string) *log.Logger {
	logPrefix := fmt.Sprintf("[%s] ", extensionName)
	debugLogger := log.New(os.Stderr, logPrefix, log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	if !debug {
		debugLogger.SetOutput(ioutil.Discard)
	}
	return debugLogger
}

func GetExtensionRoot() (string, error) {
	exPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	dirPath := filepath.Dir(exPath)
	return dirPath, nil
}

func DeserExtensionMetadata(extensionMetadataPath string) (*ExtensionMetadata, error) {
	bytes, err := os.ReadFile(extensionMetadataPath)
	if err != nil {
		return nil, err
	}

	var extMeta ExtensionMetadata
	err = json.Unmarshal(bytes, &extMeta)
	if err != nil {
		return nil, err
	}

	return &extMeta, nil
}
