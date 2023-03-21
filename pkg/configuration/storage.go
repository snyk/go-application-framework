package configuration

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/internal/utils"
)

type Storage interface {
	Set(key string, value any) error
}

type EmptyStorage struct{}

func (e *EmptyStorage) Set(_ string, _ any) error {
	return nil
}

type JsonStorage struct {
	path string
}

func NewJsonStorage(path string) *JsonStorage {
	return &JsonStorage{
		path: path,
	}
}

func (s *JsonStorage) Set(key string, value any) error {
	// Check if path to file exists
	err := os.MkdirAll(filepath.Dir(s.path), utils.FILEPERM_755)
	if err != nil {
		return err
	}

	fileBytes, err := os.ReadFile(s.path)
	if err != nil {
		const emptyJson = "{}"
		fileBytes = []byte(emptyJson)
	}

	config := make(map[string]any)
	err = json.Unmarshal(fileBytes, &config)
	if err != nil {
		return err
	}

	config[key] = value
	configJson, err := json.Marshal(config)
	if err != nil {
		return err
	}
	err = os.WriteFile(s.path, configJson, utils.FILEPERM_666)

	return err
}
