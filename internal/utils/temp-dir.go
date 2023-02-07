package utils

import (
	"log"
	"path"
)

// Gets the system temp directory and, if it doesn't exist, attempts to create it.
func systemTempDirectory(debugLogger *log.Logger, osUtil SnykOSUtil) (string, error) {
	tempDir := osUtil.TempDir()
	// make sure this directory exists
	debugLogger.Println("system temp directory:", tempDir)
	_, err := osUtil.Stat(tempDir)
	if err != nil {
		debugLogger.Println("system temp directory does not exist... attempting to create it:", tempDir)
		err = osUtil.MkdirAll(tempDir, FILEPERM_755)
		if err != nil {
			debugLogger.Println("failed to create system temp directory:", tempDir)
			return "", err
		}
	}

	return tempDir, nil
}

func snykTempDirectoryImpl(debugLogger *log.Logger, osUtil SnykOSUtil) (string, error) {
	tempDir, err := systemTempDirectory(debugLogger, osUtil)
	if err != nil {
		return "", err
	}

	snykTempDir := path.Join(tempDir, "snyk")

	// make sure it exists
	_, err = osUtil.Stat(snykTempDir)
	if err != nil {
		debugLogger.Println("snyk temp directory does not exist... attempting to create it:", snykTempDir)
		err = osUtil.MkdirAll(snykTempDir, FILEPERM_755)
		if err != nil {
			debugLogger.Println("failed to create snyk temp directory:", snykTempDir)
			return "", err
		}
	}

	return snykTempDir, nil
}

func SnykTempDirectory(debugLogger *log.Logger) (string, error) {
	osutil := NewSnykOSUtil()
	return snykTempDirectoryImpl(debugLogger, osutil)
}
