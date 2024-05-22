package utils

import (
	"crypto/sha256"
	"encoding/hex"
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
	repoUrl := sanitiseCredentials(remote.Config().URLs[0])

	if repoUrl == "" {
		return getFileSystemId(path, folderName, location)
	}

	formattedString := strings.Replace(strings.Replace(strings.Replace(strings.Replace(repoUrl, ":", "/", -1), ".git", "", -1), "@", "/", -1), "https///", "git/", -1)

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

func sanitiseCredentials(rawUrl string) string {
	parsedURL, err := url.Parse(rawUrl)
	if err != nil {
		return rawUrl
	}

	parsedURL.User = nil
	strippedUrl := parsedURL.String()

	return strippedUrl
}
