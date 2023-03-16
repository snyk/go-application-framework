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

	fileBytes, _ := os.ReadFile(s.path)
	config := make(map[string]any)
	_ = json.Unmarshal(fileBytes, &config)
	config[key] = value
	configJson, _ := json.Marshal(config)
	_ = os.WriteFile(s.path, configJson, utils.FILEPERM_666)

	return nil
}
