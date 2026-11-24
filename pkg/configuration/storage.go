package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/sync/semaphore"

	"github.com/snyk/go-application-framework/internal/fileperms"
)

//go:generate go tool github.com/golang/mock/mockgen -source=storage.go -destination ../mocks/config_storage.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/

// Storage persists configuration values that outlive a single process run.
type Storage interface {
	Set(key string, value any) error
	Refresh(config Configuration, key string) error
	// Lock acquires exclusive access to the storage across both goroutines and processes,
	// giving up when ctx is done. It is not re-entrant: calling Lock again while holding
	// the lock blocks until ctx is done.
	Lock(ctx context.Context, retryDelay time.Duration) error
	// Unlock releases the lock. It must only be called after a successful Lock.
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

// keyDeleted is a marker value which, when set, causes a key to be deleted from
// stored configuration.
var keyDeleted = struct{}{}

// IsKeyDeleted reports whether val is the internal key-deleted marker used by Unset().
func IsKeyDeleted(val any) bool {
	return val == keyDeleted
}

// withBlankFileAsEmpty makes Set treat a file that holds only white space like an empty file. It is off by default.
func withBlankFileAsEmpty() JsonOption {
	return func(s *JsonStorage) { s.blankFileAsEmpty = true }
}

// withExactNumbers makes Set keep the text of every number of the file, instead of rounding it to float64. Data after the
// document is rejected in both modes, as json.Unmarshal does. It is off by default.
func withExactNumbers() JsonOption {
	return func(s *JsonStorage) { s.exactNumbers = true }
}

// fileMutexes holds one mutex per absolute, cleaned file path. Set reads and rewrites the whole file, so the writes of all
// storages of one path are serialized in this process. A symbolic link to the same file, and other processes, need the
// file lock. The map keeps one entry per path used, which is negligible for a command line tool.
var fileMutexes = struct {
	sync.Mutex
	byPath map[string]*sync.Mutex
}{byPath: map[string]*sync.Mutex{}}

func fileMutex(path string) *sync.Mutex {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	key := filepath.Clean(path)

	fileMutexes.Lock()
	defer fileMutexes.Unlock()
	mu, ok := fileMutexes.byPath[key]
	if !ok {
		mu = &sync.Mutex{}
		fileMutexes.byPath[key] = mu
	}
	return mu
}

// isBlankJSON reports whether data holds only the white space JSON allows: space, tab, carriage return and line feed.
func isBlankJSON(data []byte) bool {
	return len(bytes.Trim(data, " \t\r\n")) == 0
}

type JsonStorage struct {
	path   string
	config Configuration

	// blankFileAsEmpty treats a file that holds only white space like an empty file.
	blankFileAsEmpty bool
	// exactNumbers keeps the text of the numbers of the file when a key is written.
	exactNumbers bool

	fileInterProcessLock *flock.Flock
	// fileInProcessLock is a semaphore rather than a sync.Mutex so Lock can give up when ctx is done.
	fileInProcessLock *semaphore.Weighted
}

type JsonOption func(*JsonStorage)

func WithConfiguration(c Configuration) JsonOption {
	return func(storage *JsonStorage) {
		storage.config = c
	}
}

func NewJsonStorage(path string, options ...JsonOption) *JsonStorage {
	storage := &JsonStorage{
		path:                 path,
		fileInterProcessLock: flock.New(path + ".lock"),
		fileInProcessLock:    semaphore.NewWeighted(1),
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
	mu := fileMutex(s.path)
	mu.Lock()
	defer mu.Unlock()
	// Check if path to file exists
	err := os.MkdirAll(filepath.Dir(s.path), fileperms.FILEPERM_755)
	if err != nil {
		return err
	}

	fileBytes, err := os.ReadFile(s.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(fileBytes) == 0 || (s.blankFileAsEmpty && isBlankJSON(fileBytes)) {
		const emptyJson = "{}"
		fileBytes = []byte(emptyJson)
	}

	config := make(map[string]any)
	err = decodeConfig(fileBytes, &config, s.exactNumbers)
	if err != nil {
		return err
	}
	if config == nil { // the file holds the JSON literal null
		config = make(map[string]any)
	}

	if tmpKey := s.getNonEnvVarKey(key); len(tmpKey) > 0 {
		key = tmpKey
	}

	if _, ok := value.(struct{}); ok {
		// See implementation of Configuration.Unset; when marker value is set,
		// key is deleted from config before writing.
		delete(config, key)
	} else {
		config[key] = value
	}
	configJson, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return writeConfigFile(s.path, configJson)
}

// decodeConfig decodes a configuration file. With exact numbers, a number keeps its text, and data after the top-level
// value is an error, as json.Unmarshal reports it.
func decodeConfig(data []byte, config *map[string]any, exactNumbers bool) error {
	if !exactNumbers {
		return json.Unmarshal(data, config)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(config); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid data after the top-level value")
	}
	return nil
}

// ensureFilePermissions removes non-owner permissions without failing reads if repair fails.
func (s *JsonStorage) ensureFilePermissions() {
	info, err := os.Stat(s.path)
	if err != nil {
		return
	}
	if mode := info.Mode().Perm() & fileperms.FILEPERM_600; mode != info.Mode().Perm() {
		_ = os.Chmod(s.path, mode) //nolint:errcheck // Permission repair is best effort when reading.
	}
}

var renameConfigFile = os.Rename

// writeConfigFile replaces the file in one step, so a crash or a full disk never leaves it truncated.
// An existing regular file that may not be replaced, such as a bind-mounted file, one in a read-only
// directory or one another process holds open on Windows, is written in place instead; see canFallBack.
func writeConfigFile(path string, contents []byte) error {
	path, err := resolveConfigPath(path)
	if err != nil {
		return err
	}
	existing, statErr := os.Stat(path)
	canOverwrite := statErr == nil && existing.Mode().IsRegular()
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		if canOverwrite && canFallBack(err) {
			return overwriteConfigFile(path, contents)
		}
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err = tmp.Chmod(fileperms.FILEPERM_600); err == nil {
		_, err = tmp.Write(contents)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if canOverwrite {
		matchOwner(tmp.Name(), existing)
	}
	if err = renameConfigFile(tmp.Name(), path); err != nil && canOverwrite && canFallBack(err) {
		return overwriteConfigFile(path, contents)
	}
	return err
}

// maxSymlinkHops is a generous bound; the OS applies its own limit when Set reads the file first.
const maxSymlinkHops = 40

// resolveConfigPath follows a symlinked configuration file, which a rename would otherwise replace,
// up to the first missing target so the write creates it as an in-place write does. A loop or too
// many hops is an error, as it would be for any other access.
func resolveConfigPath(path string) (string, error) {
	resolved := path
	seen := map[string]bool{}
	for !seen[resolved] && len(seen) <= maxSymlinkHops {
		if !isSymlink(resolved) {
			return resolved, nil
		}
		seen[resolved] = true
		target, err := os.Readlink(resolved)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			linkDir, _ := filepath.Split(resolved)
			target = linkDir + osResolveTarget(target)
		}
		if resolved, err = physicalPath(target); err != nil {
			return "", err
		}
	}
	return "", &fs.PathError{Op: "readlink", Path: path, Err: syscall.ELOOP}
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&fs.ModeSymlink != 0
}

// physicalPath resolves every component but the last, which may not exist yet, as the kernel does.
// filepath.Join and Clean would drop ".." lexically and so misplace it after a symlinked directory.
func physicalPath(path string) (string, error) {
	parent, name := filepath.Split(path)
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, name), nil
}

func overwriteConfigFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, fileperms.FILEPERM_600)
	if err != nil {
		return err
	}
	// Restrict existing files before truncating or writing credentials.
	if err = file.Chmod(fileperms.FILEPERM_600); err == nil {
		err = file.Truncate(0)
	}
	if err == nil {
		_, err = file.Write(contents)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (s *JsonStorage) Refresh(config Configuration, key string) error {
	s.ensureFilePermissions()
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
	if err := s.fileInProcessLock.Acquire(ctx, 1); err != nil {
		return err
	}

	// The lock file lives next to the config file, whose directory may not exist yet.
	err := os.MkdirAll(filepath.Dir(s.path), fileperms.FILEPERM_755)
	if err == nil {
		_, err = s.fileInterProcessLock.TryLockContext(ctx, retryDelay)
	}
	if err != nil {
		s.fileInProcessLock.Release(1)
		return err
	}

	return nil
}

func (s *JsonStorage) Unlock() error {
	err := s.fileInterProcessLock.Unlock()
	s.fileInProcessLock.Release(1)
	return err
}
