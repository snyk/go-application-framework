package instrumentation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

const (
	FilesystemTargetId   TargetIdType = 0x02 // require filesystem type target id otherwise fail
	GitTargetId          TargetIdType = 0x01 // require git type target id otherwise fail
	AutoDetectedTargetId TargetIdType = 0xff // automatically detect the target id type, trying git first and falling back to filesystem
)

const (
	RemoteRepoUrlFlagname = "remote-repo-url"
)

type TargetIdType int
type TargetIdOptions func(id *url.URL) (*url.URL, error)

func WithSubPath(subpath string) TargetIdOptions {
	result := func(id *url.URL) (*url.URL, error) {
		id.Fragment = subpath
		return id, nil
	}
	return result
}

func WithConfiguredRepository(config configuration.Configuration) TargetIdOptions {
	result := func(id *url.URL) (*url.URL, error) {
		remoteUrl := config.GetString(RemoteRepoUrlFlagname)
		if len(remoteUrl) > 0 {
			const unknownValue = "unknown"
			err := gitUpdateId(remoteUrl, unknownValue, unknownValue, id)
			if err != nil {
				return nil, err
			}
		}

		return id, nil
	}
	return result
}

func WithLineNumber(line int) TargetIdOptions {
	result := func(id *url.URL) (*url.URL, error) {
		q := id.Query()
		q.Add("line", fmt.Sprintf("%d", line))
		id.RawQuery = q.Encode()
		return id, nil
	}
	return result
}

// GetTargetId generates an identifier for a given path. The format and components of the ID
// vary depending on whether the path points to a git repository or a file system location.
//
//	scheme:type/namespace/name@version?qualifiers#subpath
//
// The URL scheme is always "pkg".
//
// For git repositories, the URL structure is as follows:
//
//	pkg:git/namespace@version?branch=branchname[subpath]
//
//	- namespace: MUST be the hostname and path of the repository (e.g., "github.com/user/repo")
//	- name: MUST be the project name (derived from the repository URL)
//	- version: MUST be the commit hash
//	- branch (qualifiers): MUST be the branch name
//	- subpath (optional): COULD specify a path or file within the repository
//	- issue (qualifiers) (optional): COULD specify an issue ID
//	- line (qualifiers) (optional): COULD specify a line number, often used with issue qualifiers
//
// Example for a git repository:
//
//	pkg:git/github.com/snyk/go-application-framework@c9cc908c69bc6d8cc4715275f9c19fa3be69aebc?branch=main
//
// Example for a file within a git repository:
//
//	pkg:git/github.com/snyk/go-application-framework@c9cc908c69bc6d8cc4715275f9c19fa3be69aebc?branch=main#cliv2/go.mod
//
// For file system locations, the URL structure is as follows:
//
//	pkg:filesystem/namespace/name[subpath]
//
//	- namespace: MUST be the SHA-256 sum of the absolute path to the root package/folder
//	- name: MUST be the last folder name in the path
//	- subpath (optional): COULD specify a path or file within the directory
//
// Example for a file system location:
//
//	pkg:filesystem/aafc908c69bc6d8cc4715275f9c19fa3be69aebc/name#cliv2/go.mod
//
// Parameters:
// - path: The file system path to generate the target id for.
// - idType: one of the available TargetIdType
// - options: optional values to assign to the target id
//
// Returns:
// A string representing the target id
func GetTargetId(path string, idType TargetIdType, options ...TargetIdOptions) (string, error) {
	var targetId *url.URL
	var err error

	// create git type id
	if idType&GitTargetId != 0 {
		targetId, err = gitBaseId(path)
	}

	// create filesystem type id
	if idType&FilesystemTargetId != 0 && targetId == nil {
		targetId, err = filesystemBaseId(path)
	}

	if targetId == nil {
		return "", fmt.Errorf("target id couldn't be determined %w", err)
	}

	// apply options
	for _, opt := range options {
		targetId, err = opt(targetId)
		if err != nil {
			return "", err
		}
	}

	return targetId.String(), nil
}

func emptyTargetId() *url.URL {
	t := &url.URL{
		Scheme:   "pkg",
		OmitHost: true,
	}
	return t
}

func gitBaseIdFromRemote(repoUrl string) (string, error) {
	if strings.HasPrefix(repoUrl, "git@") {
		formattedString := strings.ReplaceAll(repoUrl, "@", "/")
		formattedString = strings.ReplaceAll(formattedString, ":", "/")
		formattedString = strings.ReplaceAll(formattedString, ".git", "")
		return formattedString, nil
	}

	u, err := url.Parse(repoUrl)
	if err == nil {
		// Adjust the scheme
		u.Scheme = "git"
		u.User = nil

		// Adjust the host and path
		hostPath := strings.Replace(u.Host+u.Path, ":", "/", 1)
		hostPath = strings.TrimSuffix(hostPath, ".git")

		// Reassemble the URL
		formattedString := u.Scheme + "/" + hostPath
		return formattedString, nil
	}

	return "", fmt.Errorf("unknown repoUrl format %s", repoUrl)
}

func filesystemBaseId(path string) (*url.URL, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	folderName := filepath.Base(path)
	if len(filepath.Ext(path)) > 0 {
		folderName = filepath.Base(filepath.Dir(path))
	}
	t := emptyTargetId()
	t.Path = "filesystem/" + generateSHA256(path) + "/" + folderName
	return t, nil
}

func gitBaseId(path string) (*url.URL, error) {
	repo, remoteConfig, err := git.RepoFromDir(path)
	if err != nil {
		return nil, err
	}

	repoUrl := remoteConfig.URLs[0]

	// ... retrieves the branch pointed by HEAD
	ref, err := repo.Head()
	if err != nil {
		return nil, err
	}

	branchName := ""

	if ref.Name().IsBranch() {
		branchName = ref.Name().Short()
	}

	result := emptyTargetId()
	hash := ref.Hash().String()

	err = gitUpdateId(repoUrl, hash, branchName, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func gitUpdateId(repoUrl string, hash string, branchName string, result *url.URL) error {
	formattedString, err := gitBaseIdFromRemote(repoUrl)
	if err != nil {
		return err
	}

	result.Path = formattedString + "@" + hash

	q := result.Query()
	q.Set("branch", branchName)
	result.RawQuery = q.Encode()

	return nil
}

func generateSHA256(path string) string {
	hash := sha256.Sum256([]byte(path))
	return hex.EncodeToString(hash[:])
}
