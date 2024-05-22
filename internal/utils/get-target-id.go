package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

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
//
// Returns:
// A string representing the target id
func GetTargetId(path string) string {
	folderName := filepath.Base(path)
	location := getLocation(path)

	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})

	if err != nil {
		return getFileSystemId(path, folderName, location)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return getFileSystemId(path, folderName, location)
	}

	// based on the docs, the first URL is being used to fetch, so this is the one we use
	repoUrl := remote.Config().URLs[0]

	if repoUrl == "" {
		return getFileSystemId(path, folderName, location)
	}

	formattedString, err := formatRepoURL(repoUrl)
	if err != nil {
		return getFileSystemId(path, folderName, location)
	}

	// ... retrieves the branch pointed by HEAD
	ref, err := repo.Head()
	if err != nil {
		return getFileSystemId(path, folderName, location)
	}

	branchName := ""

	if ref.Name().IsBranch() {
		branchName = ref.Name().Short()
	}

	return "pkg:" + formattedString + "@" + ref.Hash().String() + "?branch=" + branchName + location
}

func formatRepoURL(repoUrl string) (string, error) {
	u, err := url.Parse(repoUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing URL: %w", err)
	}

	// Adjust the scheme
	if u.Scheme == "https" {
		u.Scheme = "git"
	}

	// Remove the user info if present
	if u.User != nil {
		u.User = nil
	}

	// Adjust the host and path
	hostPath := strings.Replace(u.Host+u.Path, ":", "/", 1)
	hostPath = strings.TrimSuffix(hostPath, ".git")

	// Reassemble the URL
	formattedString := u.Scheme + "/" + hostPath

	return formattedString, nil
}

func getLocation(path string) string {
	if len(filepath.Ext(path)) > 0 {
		return "#" + url.QueryEscape(filepath.Base(path))
	}

	return ""
}

func getFileSystemId(path string, folderName string, location string) string {
	if len(filepath.Ext(path)) > 0 {
		folderName = filepath.Base(filepath.Dir(path))
	}
	return "pkg:filesystem/" + generateSHA256(path) + "/" + folderName + location
}

func generateSHA256(path string) string {
	hash := sha256.Sum256([]byte(path))
	return hex.EncodeToString(hash[:])
}
