package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/cli"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const profileExt = ".json"

var namePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

type fileRegistry struct {
	dir    string
	base   configuration.Configuration
	logger zerolog.Logger

	mu       sync.Mutex
	profiles map[string]*profileImpl
}

var _ Registry = (*fileRegistry)(nil)

// FileRegistryOption configures a registry that NewFileRegistry returns.
type FileRegistryOption func(*fileRegistry)

// WithLogger makes the registry log, at debug level, each profile that has no file, once per profile name. A nil logger
// logs nothing.
func WithLogger(logger *zerolog.Logger) FileRegistryOption {
	return func(r *fileRegistry) {
		if logger != nil {
			r.logger = *logger
		}
	}
}

// NewFileRegistry returns a registry that reads each profile from dir/<name>.json, where dir is the profile directory
// itself. The default profile is base itself, and every other profile is derived from base. dir must be absolute, and
// it is not created: a profile file is created by the first persisted write of its profile. An empty or relative dir
// returns SNYK-CLI-0036.
func NewFileRegistry(dir string, base configuration.Configuration, opts ...FileRegistryOption) (Registry, error) {
	if dir == "" {
		return nil, cli.NewConfigProfileDirectoryInvalidError(
			fmt.Sprintf("The profile directory is not set. Set %s to an absolute path.", DirKey),
		)
	}
	if !filepath.IsAbs(dir) {
		return nil, cli.NewConfigProfileDirectoryInvalidError(
			fmt.Sprintf("The profile directory must be an absolute path. Set %s to one.", DirKey),
		)
	}
	r := &fileRegistry{
		dir:      dir,
		base:     base,
		logger:   zerolog.Nop(),
		profiles: make(map[string]*profileImpl),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

func (r *fileRegistry) Profile(name string) (Profile, error) {
	if !namePattern.MatchString(name) {
		return nil, cli.NewInvalidConfigProfileNameError(
			fmt.Sprintf(`Profile name %q is invalid: use lowercase letters, digits, "-" or "_".`, name),
		)
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
	switch {
	case errors.Is(err, os.ErrNotExist):
		// a missing file is an empty profile; the storage creates the file on the first persisted write. Only the first
		// load of a name logs it, as the profile is cached.
		r.logger.Debug().Msgf("profile %q has no file yet, using an empty profile (%s)", name, path)
	case err != nil:
		return nil, directoryError(err)
	case !info.Mode().IsRegular():
		return nil, unreadableError(name, "it is not a regular file")
	default:
		// an unreadable or invalid file must not pass as an empty profile, or the command would run with the defaults
		if err = checkProfileFile(name, path); err != nil {
			return nil, err
		}
	}

	config, err := configuration.Derive(r.base, configuration.WithPinnedFile(path))
	if err != nil {
		return nil, cli.NewConfigProfilesUnavailableError(fmt.Sprintf("Profile %q cannot be loaded.", name))
	}
	return &profileImpl{name: name, config: config}, nil
}

// unreadableError reports a profile file that cannot be used. It has no cause, because an OS error carries the path.
func unreadableError(name, why string) error {
	return cli.NewConfigProfileUnreadableError(fmt.Sprintf("Profile %q cannot be read: %s.", name, why))
}

// directoryError reports a profile directory that cannot be used, because of an OS error. Its detail never contains a
// path, and it has no cause, because the OS error carries one.
func directoryError(err error) error {
	return cli.NewConfigProfileDirectoryInvalidError(
		fmt.Sprintf("The profile directory cannot be used: %s.", osText(err)),
	)
}

// osText is the reason of an OS error for a detail sentence, without the path that os.Lstat, os.Stat and os.ReadFile
// add to it, and without the period that Windows ends it with.
func osText(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return strings.TrimRight(err.Error(), ". ")
}

// checkProfileFile returns the error when the profile file cannot be used, and nil when it can. The error has no cause,
// so the path of the file does not reach the marshal error.
func checkProfileFile(name, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return unreadableError(name, osText(err))
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	var value any
	if err = json.Unmarshal(content, &value); err != nil {
		return unreadableError(name, "the file is not valid JSON")
	}
	if _, ok := value.(map[string]any); !ok {
		return unreadableError(name, "the file is not a JSON object")
	}
	return nil
}
