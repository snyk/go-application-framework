package extension

import (
	"fmt"
	"os"
	"path"
	"runtime"
)

type Extension struct {
	Root     string
	BinPath  string
	Metadata *ExtensionMetadata
}

// Load an extension from the given directory
func TryLoad(dirPath string) (*Extension, error) {
	dirPathStat, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("extension root directory does not exist: %s", dirPath)
	}

	// make sure it's actually a directory
	if !dirPathStat.IsDir() {
		return nil, fmt.Errorf("extension root directory is not a directory: %s", dirPath)
	}

	extensionMetadataPath := path.Join(dirPath, "extension.json")
	_, err = os.Stat(extensionMetadataPath)
	if err != nil {
		return nil, fmt.Errorf("extension metadata file does not exist: %s", extensionMetadataPath)
	}

	// deserialize the extension metadata
	metadata, err := DeserExtensionMetadataFromFile(extensionMetadataPath)
	if err != nil {
		return nil, fmt.Errorf("error deserializing extension metadata: %s", err)
	}

	binFilename := fmt.Sprintf("%s_%s", metadata.Name, binarySuffix())
	binPath := path.Join(dirPath, binFilename)

	extension := Extension{
		Root:     dirPath,
		BinPath:  binPath,
		Metadata: metadata,
	}

	return &extension, nil
}

func binarySuffix() string {
	return fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
}
