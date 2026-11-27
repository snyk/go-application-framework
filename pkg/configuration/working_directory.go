package configuration

import (
	"fmt"
	"os"
	"path/filepath"
)

// WorkingDirConfigFileWarning returns a warning message when a configuration file of config is in the working directory
// and the one in the configstore directory does not exist. It returns an empty string otherwise.
func WorkingDirConfigFileWarning(config Configuration) string {
	for _, name := range config.GetFiles() {
		if name == "" {
			continue
		}
		cfgFile := name + "." + configFileType

		configStoreAvailable := true
		storeDir, err := basePath()
		if err != nil {
			configStoreAvailable = false
		} else {
			configFilePath := filepath.Join(storeDir, cfgFile)
			if info, statErr := os.Stat(configFilePath); statErr != nil || !info.Mode().IsRegular() {
				configStoreAvailable = false
			}
		}

		workingDirConfigFileAvailable := true
		var ignored string
		workingDir, err := os.Getwd()
		if err != nil {
			workingDirConfigFileAvailable = false
		} else {
			ignored = filepath.Join(workingDir, cfgFile)
			if info, statErr := os.Stat(ignored); statErr != nil || !info.Mode().IsRegular() {
				workingDirConfigFileAvailable = false
			}
		}

		if !configStoreAvailable && workingDirConfigFileAvailable {
			return fmt.Sprintf("The expected configuration file does not exist, and %s is ignored for security reasons. To use it, configure its absolute path explicitly.",
				ignored)
		}
	}

	return ""
}
