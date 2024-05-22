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
