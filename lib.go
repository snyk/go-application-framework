package cli_extension_lib_go

import (
	"bufio"
	"fmt"
	"github.com/snyk/cli-extension-lib-go/extension"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// Returns the full path to the directory containing the extension binary
func ExtensionRoot() (string, error) {
	exPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	dirPath := filepath.Dir(exPath)
	return dirPath, nil
}

func DebugLogger(debug bool, extensionName string) *log.Logger {
	logPrefix := fmt.Sprintf("[%s] ", extensionName)
	debugLogger := log.New(os.Stderr, logPrefix, log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	if !debug {
		debugLogger.SetOutput(ioutil.Discard)
	}
	return debugLogger
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

// This is for an extension to call to init the extension
func InitExtension() (*extension.Extension, *ExtensionInput, error) {
	extensionRoot, err := ExtensionRoot()
	if err != nil {
		return nil, nil, err
	}

	stdinReader := bufio.NewReader(os.Stdin)
	return InitExtensionWithArgs(extensionRoot, stdinReader)
}

// An abstraction on InitExtension for better testability
func InitExtensionWithArgs(extensionRoot string, reader io.RuneReader) (*extension.Extension, *ExtensionInput, error) {
	ext, err := extension.TryLoad(extensionRoot)
	if err != nil {
		return nil, nil, err
	}

	inputString, err := ReadInput(reader)
	if err != nil {
		return nil, nil, err
	}

	extensionInput, err := DeserExtensionInput(inputString)
	if err != nil {
		return nil, nil, err
	}

	return ext, extensionInput, nil
}
