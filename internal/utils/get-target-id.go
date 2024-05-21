package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

func GetTargetId(path string) (string, error) {
	folderName := filepath.Base(path)
	location := ""

	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})

	if err != nil {
		if len(filepath.Ext(path)) > 0 {
			folderName = filepath.Base(filepath.Dir(path))
			location = "#" + filepath.Base(path)
		}

		return "pkg:filesystem/" + generateSHA256(path) + "/" + folderName + location, nil
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("get remote: %w", err)
	}

	// based on the docs, the first URL is being used to fetch, so this is the one we use
	repoUrl := remote.Config().URLs[0]

	formattedString := strings.Replace(strings.Replace(strings.Replace(strings.Replace(repoUrl, ":", "/", -1), ".git", "", -1), "@", "/", -1), "https///", "git/", -1)

	// ... retrieves the branch pointed by HEAD
	ref, _ := repo.Head()

	branchName := ""

	if ref.Name().IsBranch() {
		branchName = ref.Name().Short()
	}

	return "pkg:" + formattedString + "@" + ref.Hash().String() + "?branch=" + branchName, nil
}

func generateSHA256(path string) string {
	hash := sha256.Sum256([]byte(path))
	return hex.EncodeToString(hash[:])
}
