package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
)

func GetTargetId(path string) (string, error) {
	folderName := filepath.Base(path)
	location := ""

	if len(filepath.Ext(path)) > 0 {
		folderName = filepath.Base(filepath.Dir(path))
		location = "#" + filepath.Base(path)
	}

	return "pkg:filesystem/" + generateSHA256(path) + "/" + folderName + location, nil
}

func generateSHA256(path string) string {
	hash := sha256.Sum256([]byte(path))
	return hex.EncodeToString(hash[:])
}
