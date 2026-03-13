package configresolver

// Key prefix constants. Colons are safe as viper's delimiter is ".".
const (
	PrefixUser   = "user"
	PrefixRemote = "remote"
	PrefixFolder = "folder"
)

// UserGlobalKey returns the key for a user-set global value.
// Format: user:global:<name>
func UserGlobalKey(name string) string {
	return PrefixUser + ":global:" + name
}

// UserFolderKey returns the key for a user-set folder override.
// Format: user:folder:<folderPath>:<name>
func UserFolderKey(folderPath, name string) string {
	return PrefixUser + ":folder:" + folderPath + ":" + name
}

// RemoteOrgKey returns the key for org-level remote config (LDX-Sync).
// Format: remote:<orgId>:<name>
func RemoteOrgKey(orgID, name string) string {
	return PrefixRemote + ":" + orgID + ":" + name
}

// RemoteOrgFolderKey returns the key for per-folder remote config within an org.
// Format: remote:<orgId>:folder:<folderPath>:<name>
func RemoteOrgFolderKey(orgID, folderPath, name string) string {
	return PrefixRemote + ":" + orgID + ":folder:" + folderPath + ":" + name
}

// RemoteMachineKey returns the key for machine-level remote config.
// Format: remote:machine:<name>
func RemoteMachineKey(name string) string {
	return PrefixRemote + ":machine:" + name
}

// FolderMetadataKey returns the key for folder metadata (preferred_org, base_branch, etc.).
// Format: folder:<folderPath>:<metaName>
func FolderMetadataKey(folderPath, metaName string) string {
	return PrefixFolder + ":" + folderPath + ":" + metaName
}
