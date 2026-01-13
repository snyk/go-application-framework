package git

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
)

var originRegex = regexp.MustCompile(`(.+@)?(.+):(.+$)`)

func RepoUrlFromDir(inputDir string) (string, error) {
	_, remoteConfig, err := RepoFromDir(inputDir)
	if err != nil {
		return "", err
	}
	repoRemoteUrl := remoteConfig.URLs[0]
	return repoRemoteUrl, nil
}

func BranchNameFromDir(inputDir string) (string, error) {
	repo, _, err := RepoFromDir(inputDir)
	if err != nil {
		return "", err
	}
	ref, err := repo.Head()
	if err != nil {
		return "", err
	}

	if ref.Name().IsBranch() {
		return ref.Name().Short(), nil
	}
	return "", nil
}

func RepoFromDir(inputDir string) (*git.Repository, *config.RemoteConfig, error) {
	repo, err := git.PlainOpenWithOptions(inputDir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})

	if err != nil {
		return nil, nil, err
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return nil, nil, err
	}

	// based on the docs, the first URL is being used to fetch, so this is the one we use
	remoteConfig := remote.Config()
	if remoteConfig == nil || len(remoteConfig.URLs) == 0 || remoteConfig.URLs[0] == "" {
		return repo, nil, fmt.Errorf("no remote url found")
	}
	return repo, remoteConfig, nil
}

// GetRemoteUrl retrieves the appropriate remote URL for LDX-Sync resolution.
// Priority: origin remote first, then first available remote.
//
// Parameters:
//   - inputDir (string): The directory path to check for git repository
//
// Returns:
//   - The remote URL as a string.
//   - An error object (if no git repository found or no remotes configured).
func GetRemoteUrl(inputDir string) (string, error) {
	// Try to get origin remote first
	originUrl, err := GetOriginRemote(inputDir)
	if err == nil {
		return originUrl, nil
	}

	// Fallback to first available remote
	return GetFirstRemote(inputDir)
}

// GetOriginRemote retrieves the origin remote URL from a git repository.
//
// Parameters:
//   - inputDir (string): The directory path to check for git repository
//
// Returns:
//   - The origin remote URL as a string.
//   - An error object (if no git repository found or no origin remote configured).
func GetOriginRemote(inputDir string) (string, error) {
	repo, err := git.PlainOpenWithOptions(inputDir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("not a git repository: %w", err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("no origin remote found: %w", err)
	}

	remoteConfig := remote.Config()
	if remoteConfig == nil || len(remoteConfig.URLs) == 0 || remoteConfig.URLs[0] == "" {
		return "", fmt.Errorf("origin remote has no URL")
	}

	return remoteConfig.URLs[0], nil
}

// GetFirstRemote retrieves the first available remote URL from a git repository.
//
// Parameters:
//   - inputDir (string): The directory path to check for git repository
//
// Returns:
//   - The first remote URL as a string.
//   - An error object (if no git repository found or no remotes configured).
func GetFirstRemote(inputDir string) (string, error) {
	repo, err := git.PlainOpenWithOptions(inputDir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("not a git repository: %w", err)
	}

	remotes, err := repo.Remotes()
	if err != nil {
		return "", fmt.Errorf("failed to get remotes: %w", err)
	}

	if len(remotes) == 0 {
		return "", fmt.Errorf("no remotes configured")
	}

	// Get the first remote
	firstRemote := remotes[0]
	remoteConfig := firstRemote.Config()
	if remoteConfig == nil || len(remoteConfig.URLs) == 0 || remoteConfig.URLs[0] == "" {
		return "", fmt.Errorf("first remote has no URL")
	}

	return remoteConfig.URLs[0], nil
}

func NormalizeRemoteURL(remoteUrl string) string {
	if remoteUrl == "" {
		return remoteUrl
	}

	// for scp-like syntax [user@]server:project.git
	u, err := url.Parse(remoteUrl)
	if err == nil && u.Host != "" && u.Scheme != "" {
		scheme := strings.ToLower(u.Scheme)
		if scheme == "ssh" || scheme == "http" || scheme == "https" {
			return fmt.Sprintf("http://%s%s", u.Host, u.Path)
		}
	}

	matches := originRegex.FindStringSubmatch(remoteUrl)
	if len(matches) == 4 {
		if matches[2] != "" && matches[3] != "" {
			return fmt.Sprintf("http://%s/%s", matches[2], matches[3])
		}
	}

	return remoteUrl
}
