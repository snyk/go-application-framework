package utils

import (
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/internal/fileperms"
)

// FILEPERM_755 and FILEPERM_666 are kept here as aliases for existing consumers of this package;
// the canonical definitions live in internal/fileperms so they can be imported without an
// import cycle by packages this package itself depends on.
const (
	FILEPERM_755 = fileperms.FILEPERM_755
	FILEPERM_666 = fileperms.FILEPERM_666
)

func CreateFilePath(path string) error {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dirPath, FILEPERM_755)
		return err
	}
	return nil
}
