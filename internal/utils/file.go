package utils

import (
	"io/fs"
	"os"
	"path/filepath"
)

const (
	FILEPERM_755 fs.FileMode = 0755 // Owner=rwx, Group=r-x, Other=r-x
	FILEPERM_666 fs.FileMode = 0666 // Owner=rw-, Group=rw-, Other=rw-
)

func CreateFilePath(path string) error {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dirPath, FILEPERM_755)
		return err
	}
	return nil
}
