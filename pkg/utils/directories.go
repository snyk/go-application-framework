package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// 0755 is the default permission for directories, it means the owner can read, write, and execute,
// and everyone else can read and execute but not write.
const DIR_PERMISSION = 0755

// The directory structure used to cache things into
// - Base cache directory (user definable, default depends on OS, exmple:  /Users/username/Library/Caches/snyk/)
// |- Version cache directory (example: /Users/username/Library/Caches/snyk/snyk-cli/1.1075.0/)
// |- Temp directory (example: /Users/username/Library/Caches/snyk/snyk-cli/1.1075.0/tmp/)

func GetTemporaryDirectory(baseCacheDirectory string, versionNumber string) string {
	pid := os.Getpid()
	// filepath.Join rather than path.Join so the result uses the platform
	// separator. Callers that measure path length (Windows MAX_PATH) or compare
	// paths cannot do so reliably against a mix of both separators.
	return filepath.Join(baseCacheDirectory, versionNumber, "tmp", fmt.Sprintf("pid%d", pid))
}

func CreateAllDirectories(baseCacheDirectory string, versionNumber string) error {
	directoryList := []string{
		GetTemporaryDirectory(baseCacheDirectory, versionNumber),
	}

	for _, dir := range directoryList {
		err := os.MkdirAll(dir, DIR_PERMISSION)
		if err != nil {
			return errors.Wrap(err, "failed to create all directories.")
		}
	}

	return nil
}

// CreateDirectory creates the given directory, and any missing parent, without
// deriving any additional path segments from it.
//
// Prefer this over CreateAllDirectories when the caller already holds the final
// path: CreateAllDirectories treats its argument as a *base cache* directory and
// appends <version>/tmp/pid<PID> to it, so passing an already-complete
// temporary directory to it creates a redundant nested subtree.
func CreateDirectory(directory string) error {
	if err := os.MkdirAll(directory, DIR_PERMISSION); err != nil {
		return errors.Wrapf(err, "failed to create directory %s", directory)
	}

	return nil
}
