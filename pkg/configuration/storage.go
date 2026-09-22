package configuration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"

	"github.com/snyk/go-application-framework/internal/fileperms"
)

//go:generate go tool github.com/golang/mock/mockgen -source=storage.go -destination ../mocks/config_storage.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/

// Storage persists configuration values that outlive a single process run.
type Storage interface {
	// Set persists value under key. If IsKeyDeleted(value) is true, the implementation must
	// remove key from storage instead of persisting the value.
	Set(key string, value any) error
	Refresh(config Configuration, key string) error
	Lock(ctx context.Context, retryDelay time.Duration) error
	Unlock() error
}

type EmptyStorage struct{}

func (*EmptyStorage) Set(string, any) error {
	return nil
}

func (*EmptyStorage) Refresh(Configuration, string) error {
	return nil
}

func (*EmptyStorage) Lock(context.Context, time.Duration) error {
	return nil
}

func (*EmptyStorage) Unlock() error {
	return nil
}

// deletedMarker is a distinct type so an arbitrary struct{}{} value built by unrelated code is
// never mistaken for the Deleted sentinel below; only IsKeyDeleted(Deleted) is true.
type deletedMarker struct{}

// Deleted is the sentinel value a Storage.Set implementation must recognize, via IsKeyDeleted,
// as "remove this key" rather than a value to persist.
var Deleted any = deletedMarker{}

// IsKeyDeleted reports whether val is the Deleted sentinel used by Unset().
func IsKeyDeleted(val any) bool {
	return val == Deleted
}

type JsonStorage struct {
	path     string
	config   Configuration
	fileLock *flock.Flock
	mutex    sync.Mutex

	// inProcess and lockHeld close a gap in *flock.Flock: its OS-level lock only
	// guards against other processes, so two goroutines sharing this same
	// JsonStorage in one process would otherwise both be granted Lock() at once.
	// inProcess is a capacity-1 gate acquired by Lock and released by Unlock;
	// lockHeld records whether this instance currently holds it, so a failed
	// Lock never skews the count and an unmatched Unlock is a safe no-op.
	inProcess chan struct{}
	lockHeld  int32
}

type JsonOption func(*JsonStorage)

func WithConfiguration(c Configuration) JsonOption {
	return func(storage *JsonStorage) {
		storage.config = c
	}
}

func NewJsonStorage(path string, options ...JsonOption) *JsonStorage {
	storage := &JsonStorage{
		path:      path,
		fileLock:  flock.New(path + ".lock"),
		inProcess: make(chan struct{}, 1),
	}

	for _, opt := range options {
		opt(storage)
	}

	return storage
}

// This function deals with the fact that not every key can or shall be written to the config. Keys that belong to
// Environment Variables need to be matched to their alternative names in the config.
// For example "SNYK_TOKEN" in the config file would be "api"
// The logic should in the future be moved closer to the configuration as it might be needed there as well.
func (s *JsonStorage) getNonEnvVarKey(key string) string {
	if s.config == nil {
		return ""
	}

	keys := []string{key}
	keys = append(keys, s.config.GetAlternativeKeys(key)...)
	for _, k := range keys {
		if s.config.GetKeyType(k) != EnvVarKeyType {
			return k
		}
	}

	return ""
}

func (s *JsonStorage) Set(key string, value any) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// Check if path to file exists
	err := os.MkdirAll(filepath.Dir(s.path), fileperms.FILEPERM_755)
	if err != nil {
		return err
	}

	fileBytes, err := os.ReadFile(s.path)
	if len(fileBytes) == 0 || err != nil {
		const emptyJson = "{}"
		fileBytes = []byte(emptyJson)
	}

	config := make(map[string]any)
	err = json.Unmarshal(fileBytes, &config)
	if err != nil {
		return err
	}

	if tmpKey := s.getNonEnvVarKey(key); len(tmpKey) > 0 {
		key = tmpKey
	}

	if IsKeyDeleted(value) {
		delete(config, key)
	} else {
		config[key] = value
	}
	configJson, err := json.Marshal(config)
	if err != nil {
		return err
	}
	err = os.WriteFile(s.path, configJson, fileperms.FILEPERM_666)

	return err
}

func (s *JsonStorage) Refresh(config Configuration, key string) error {
	contents, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	doc := map[string]interface{}{}
	err = json.Unmarshal(contents, &doc)
	if err != nil {
		return err
	}
	if value, ok := doc[key]; ok {
		config.Set(key, value)
	}
	return nil
}

func (s *JsonStorage) Lock(ctx context.Context, retryDelay time.Duration) error {
	select {
	case s.inProcess <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	_, err := s.fileLock.TryLockContext(ctx, retryDelay)
	if err != nil {
		<-s.inProcess
		return err
	}

	atomic.StoreInt32(&s.lockHeld, 1)
	return nil
}

func (s *JsonStorage) Unlock() error {
	if !atomic.CompareAndSwapInt32(&s.lockHeld, 1, 0) {
		return nil
	}

	err := s.fileLock.Unlock()
	<-s.inProcess
	return err
}
