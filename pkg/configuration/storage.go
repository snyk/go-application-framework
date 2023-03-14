package configuration

import (
	"encoding/json"
	"io"
)

type JsonStorage struct {
	rw      io.ReadWriter
	decoder *json.Decoder
	encoder *json.Encoder
}

func NewJsonStorage(rw io.ReadWriter) *JsonStorage {
	return &JsonStorage{
		rw:      rw,
		decoder: json.NewDecoder(rw),
		encoder: json.NewEncoder(rw),
	}
}

func (s *JsonStorage) Set(key string, value any) error {
	config := make(map[string]any)
	_ = s.decoder.Decode(&config)
	config[key] = value
	_ = s.encoder.Encode(config)

	return nil
}
