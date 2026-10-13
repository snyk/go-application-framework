package machineid

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const (
	sourceSharedFile     = "shared machine id file"
	sourceStudioDeviceID = "Snyk Studio device-id file"
)

type scopedPath struct {
	path  string
	scope string
}

func (p pathPair) scoped() []scopedPath {
	return []scopedPath{{p.machineWide, "machine"}, {p.perUser, "user"}}
}

// unreadableFileError returns nil unless the file exists but cannot be read: a missing file and
// unusable contents are states resolution recovers from by itself, so they are only logged.
func unreadableFileError(err error, source string, c scopedPath) error {
	if err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, errNoValidID) || errors.Is(err, errFileTooLarge) {
		return nil
	}
	return cli.NewMachineIDFileUnreadableError(
		fmt.Sprintf("The %s-scope %s at %s could not be read: %v", c.scope, source, c.path, err),
		snyk_errors.WithMeta("path", c.path),
		snyk_errors.WithMeta("source", source),
		snyk_errors.WithMeta("scope", c.scope),
		snyk_errors.WithCause(err),
	)
}

func notPersistedError(writeErr error) error {
	return cli.NewMachineIDNotPersistedError(
		// writeErr joins the machine-wide and per-user failures with newlines; log consumers expect one line per error.
		"No machine id could be stored: "+strings.ReplaceAll(writeErr.Error(), "\n", "; "),
		snyk_errors.WithCause(writeErr),
	)
}
