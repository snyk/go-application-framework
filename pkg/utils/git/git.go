package git

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
)

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

// scpLikeRegex matches SCP-like git URLs: [user@]host:path
// The path must not start with / to avoid matching protocol URLs like ssh://
var scpLikeRegex = regexp.MustCompile(`^(.+@)?([^:]+):([^/].*)$`)

// GetSanitizedRemoteUrl normalizes a git remote URL to a consistent HTTP format.
// It handles standard URLs (ssh:, http:, https:) and SCP-like syntax (git@host:path).
//
// Parameters:
//   - remoteUrl (string): The git remote URL to sanitize
//
// Returns:
//   - The sanitized URL in http://{host}/{path} format, or the original URL if parsing fails
func GetSanitizedRemoteUrl(remoteUrl string) string {
	if remoteUrl == "" {
		return remoteUrl
	}

	// Try to parse as a standard URL
	parsed, err := url.Parse(remoteUrl)
	if err == nil && parsed.Host != "" && parsed.Scheme != "" {
		// Check if it's a supported protocol
		switch parsed.Scheme {
		case "ssh", "http", "https":
			return fmt.Sprintf("http://%s%s", parsed.Host, parsed.Path)
		}
		// Unsupported protocol, return as-is
		return remoteUrl
	}

	// Try to parse as SCP-like syntax: [user@]host:path
	matches := scpLikeRegex.FindStringSubmatch(remoteUrl)
	if len(matches) == 4 && matches[2] != "" && matches[3] != "" {
		host := matches[2]
		path := matches[3]
		return fmt.Sprintf("http://%s/%s", host, path)
	}

	return remoteUrl
}
