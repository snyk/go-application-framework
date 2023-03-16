package configuration

import (
	"encoding/json"
	"os"
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
	fileBytes, _ := os.ReadFile(s.path)
	config := make(map[string]any)
	json.Unmarshal(fileBytes, &config)
	config[key] = value
	configJson, _ := json.Marshal(config)
	os.WriteFile(s.path, configJson, 0666)

	return nil
}
