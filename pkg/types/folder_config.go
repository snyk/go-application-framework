package types

import "github.com/snyk/go-application-framework/pkg/product"

// ScanCommandConfig allows to define a command that is run before (PreScanCommand)
// or after (PostScanCommand) a scan. It will only be run for the
// referenceFolder / referenceScan (in case of delta) if the corresponding
// parameter PreScanOnlyReferenceFolder / PostScanOnlyReferenceFolder is set.
// Else it will run for all scans.
type ScanCommandConfig struct {
	PreScanCommand              string `json:"command,omitempty"`
	PreScanOnlyReferenceFolder  bool   `json:"preScanOnlyReferenceFolder,omitempty"`
	PostScanCommand             string `json:"postScanCommand,omitempty"`
	PostScanOnlyReferenceFolder bool   `json:"postScanOnlyReferenceFolder,omitempty"`
}

// FolderConfig is exchanged between IDE and LS
// IDE sends this as part of the settings/initialization
// LS sends this via the $/snyk.folderConfig notification
type FolderConfig struct {
	FolderPath           FilePath                              `json:"folderPath"`
	BaseBranch           string                                `json:"baseBranch"`
	LocalBranches        []string                              `json:"localBranches,omitempty"`
	AdditionalParameters []string                              `json:"additionalParameters,omitempty"`
	ReferenceFolderPath  FilePath                              `json:"referenceFolderPath,omitempty"`
	ScanCommandConfig    map[product.Product]ScanCommandConfig `json:"scanCommandConfig,omitempty"`
}
