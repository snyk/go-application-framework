package utils

import (
	"fmt"
	"os"
	"path"

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
	return path.Join(baseCacheDirectory, versionNumber, "tmp", fmt.Sprintf("pid%d", pid))
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
