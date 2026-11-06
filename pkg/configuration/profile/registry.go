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
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const profileExt = ".json"

var namePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// reservedNames are device names that Windows reserves, so they cannot be used as file names there.
var reservedNames = regexp.MustCompile(`^(con|prn|aux|nul|com[0-9]|lpt[0-9])$`)

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
// it is not created: a profile file is created by the first persisted write of its profile.
func NewFileRegistry(dir string, base configuration.Configuration, opts ...FileRegistryOption) (Registry, error) {
	if dir == "" {
		return nil, cli.NewConfigProfileDirectoryInvalidError(
			fmt.Sprintf("The profile directory is not set. Set %s to an absolute path.", DirKey),
			snyk_errors.WithCause(errors.New("profile directory is not set")),
		)
	}
	if !filepath.IsAbs(dir) {
		return nil, cli.NewConfigProfileDirectoryInvalidError(
			fmt.Sprintf("The profile directory %q cannot be used: it must be an absolute path.", dir),
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
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Windows reports a path under a regular file as not existing, so check that the directory is not a file
		dirInfo, dirErr := os.Stat(r.dir)
		switch {
		case dirErr == nil && !dirInfo.IsDir():
			return nil, directoryError("not a directory", fmt.Errorf("profile %s: %w", name, err))
		case dirErr != nil && !errors.Is(dirErr, os.ErrNotExist):
			return nil, directoryError(reason(dirErr), fmt.Errorf("profile %s: %w", name, dirErr))
		}
		// a missing file is an empty profile; the storage creates the file on the first persisted write. Only the first
		// load of a name logs it, as the profile is cached.
		r.logger.Debug().Msgf("profile %q has no file yet, using an empty profile (%s)", name, path)
	case err != nil:
		// not a problem of the file, so the cause does not wrap ErrCorrupt
		return nil, directoryError(reason(err), fmt.Errorf("profile %s: %w", name, err))
	case !info.Mode().IsRegular():
		return nil, unreadableError(name, "not a regular file", fmt.Errorf("%w: %s: not a regular file", ErrCorrupt, name))
	default:
		// an unreadable or invalid file must not pass as an empty profile, or the command would run with the defaults
		if err = checkProfileFile(path); err != nil {
			return nil, unreadableError(name, reason(err), fmt.Errorf("%w: %s: %w", ErrCorrupt, name, err))
		}
	}

	config, err := configuration.Derive(r.base, configuration.WithPinnedFile(path))
	if err != nil {
		return nil, unavailableError(name, err)
	}
	return &profileImpl{name: name, config: config}, nil
}

// maxFileNameLen is the longest file name that common file systems accept.
const maxFileNameLen = 255

func validName(name string) error {
	if !namePattern.MatchString(name) || reservedNames.MatchString(name) || len(name)+len(profileExt) > maxFileNameLen {
		return cli.NewInvalidConfigProfileNameError(
			fmt.Sprintf("%q is not a valid profile name.", name),
			snyk_errors.WithCause(fmt.Errorf("%w: %q", ErrInvalidName, name)),
		)
	}
	return nil
}

// unreadableError returns the error-catalog error for a profile file that cannot be used. The cause, which wraps
// ErrCorrupt, stays reachable with errors.Is and errors.As.
func unreadableError(name, why string, cause error) error {
	return cli.NewConfigProfileUnreadableError(
		fmt.Sprintf("The file of profile %q cannot be used: %s.", name, why),
		snyk_errors.WithCause(cause),
	)
}

// directoryError returns the error-catalog error for a profile directory that cannot be used. The detail names no path.
func directoryError(why string, cause error) error {
	return cli.NewConfigProfileDirectoryInvalidError(
		fmt.Sprintf("The profile directory cannot be used: %s.", why),
		snyk_errors.WithCause(cause),
	)
}

// unavailableError returns the error-catalog error for a profile that cannot be loaded for a reason outside the profile
// name, file and directory. The cause stays reachable with errors.Is and errors.As.
func unavailableError(name string, cause error) error {
	return cli.NewConfigProfilesUnavailableError(
		fmt.Sprintf("The configuration profile %q cannot be loaded.", name),
		snyk_errors.WithCause(cause),
	)
}

// reason returns the message of err without the file path and the Go type names that an error may carry.
func reason(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return "the file does not contain a JSON object"
	}
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
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
