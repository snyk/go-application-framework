package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	profileDirName = "profiles"
	profileExt     = ".json"
)

var namePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// reservedNames are device names that Windows reserves, so they cannot be used as file names there.
var reservedNames = regexp.MustCompile(`^(con|prn|aux|nul|com[0-9]|lpt[0-9])$`)

type fileRegistry struct {
	dir  string
	base configuration.Configuration

	mu       sync.Mutex
	profiles map[string]*profileImpl
}

var _ Registry = (*fileRegistry)(nil)

// NewFileRegistry returns a registry that reads each profile from baseDir/profiles/<name>.json. The default profile
// is base itself, and every other profile is derived from base. baseDir must be absolute, otherwise a profile
// would fall back to the default storage.
func NewFileRegistry(baseDir string, base configuration.Configuration) (Registry, error) {
	if !filepath.IsAbs(baseDir) {
		return nil, fmt.Errorf("profile base directory must be absolute: %q", baseDir)
	}
	return &fileRegistry{
		dir:      filepath.Join(baseDir, profileDirName),
		base:     base,
		profiles: make(map[string]*profileImpl),
	}, nil
}

func (r *fileRegistry) Profile(name string) (Profile, error) {
	if err := validName(name); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.profiles[name]; ok {
		return p, nil
	}
	p, err := r.load(name)
	if err != nil {
		return nil, err
	}
	r.profiles[name] = p
	return p, nil
}

// load must be called with the mutex held.
func (r *fileRegistry) load(name string) (*profileImpl, error) {
	if name == DefaultName {
		return &profileImpl{name: name, config: r.base}, nil
	}

	path := filepath.Join(r.dir, name+profileExt)
	// Lstat, so a symbolic link cannot make one profile an alias of another file
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	// an unreadable or invalid file must not pass as an empty profile, or the command would run with the defaults
	if err = checkProfileFile(path); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, name, err)
	}

	config, err := configuration.Derive(r.base, configuration.WithPinnedFile(path))
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}
	return &profileImpl{name: name, config: config}, nil
}

func validName(name string) error {
	if !namePattern.MatchString(name) || reservedNames.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

// checkProfileFile reports whether the file is empty or holds a JSON object.
func checkProfileFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	var values map[string]any
	if err := json.Unmarshal(content, &values); err != nil {
		return err
	}
	if values == nil {
		return errors.New("not a JSON object")
	}
	return nil
}
