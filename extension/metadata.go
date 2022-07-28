package extension

import (
	"encoding/json"
	"os"
)

type ExtensionMetadata struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Command     *Command `json:"command"`
}

type Command struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Options     []CommandOption     `json:"options"`
	Subcommands map[string]*Command `json:"subcommands"`
}

type CommandOption struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Default     any    `json:"default"`
	Required    bool   `json:"required"`
}

func DeserExtensionMetadataFromFile(extensionMetadataPath string) (*ExtensionMetadata, error) {
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
