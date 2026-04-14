package git

import (
	"fmt"
	"net/url"
	"strings"

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

// StripGitCredentials removes userinfo (username, password, token) from a git URL.
// For SCP-style URLs (user@host:path), the user@ portion is stripped since it may
// contain tokens used as usernames. For scheme:// URLs, the standard userinfo is
// removed. If url.Parse fails (e.g., malformed port), a pattern-based fallback
// strips credentials from the raw string to prevent leakage.
func StripGitCredentials(rawUrl string) string {
	if rawUrl == "" {
		return rawUrl
	}

	return stripGitCredentials(rawUrl, isSCPStyle(rawUrl))
}

func stripGitCredentials(rawUrl string, scpStyle bool) string {
	if rawUrl == "" {
		return rawUrl
	}

	// SCP-style URLs (user@host:path) — strip the user@ portion.
	// The result is used for logging/API calls, not SSH connections,
	// so removing the username is safe and prevents token-as-username leakage.
	if scpStyle {
		atIdx := strings.Index(rawUrl, "@")
		colonIdx := strings.Index(rawUrl, ":")
		if atIdx < 0 || colonIdx < 0 || atIdx > colonIdx {
			return rawUrl
		}
		return rawUrl[atIdx+1:]
	}

	u, err := url.Parse(rawUrl)
	if err != nil {
		// url.Parse failed (e.g., invalid port) — fall back to pattern-based stripping
		return stripCredentialsByPattern(rawUrl)
	}

	if u.User != nil {
		u.User = nil
		return u.String()
	}

	return rawUrl
}

// stripCredentialsByPattern removes user[:pass]@ from a URL string using pattern matching.
// Used as a fallback when url.Parse fails on malformed URLs that still contain credentials.
func stripCredentialsByPattern(rawUrl string) string {
	schemeEnd := strings.Index(rawUrl, "://")
	if schemeEnd < 0 {
		return rawUrl
	}
	rest := rawUrl[schemeEnd+3:]

	authorityEnd := strings.Index(rest, "/")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority := rest[:authorityEnd]
	atIdx := strings.LastIndex(authority, "@")
	if atIdx < 0 {
		return rawUrl
	}

	return rawUrl[:schemeEnd+3] + authority[atIdx+1:] + rest[authorityEnd:]
}

// NormalizeGitURL converts any git remote URL format (SSH, SCP-style, git://, http://)
// into a consistent https:// URL with credentials removed and .git suffix stripped.
// If the URL cannot be parsed, the credential-stripped input is returned as-is.
func NormalizeGitURL(rawUrl string) string {
	if rawUrl == "" {
		return rawUrl
	}

	scpStyle := isSCPStyle(rawUrl)

	// Handle SCP-style on the original input before credential stripping.
	// StripGitCredentials turns user@host:path into host:path, which url.Parse
	// would misinterpret as scheme:path. So we extract host and path directly.
	if scpStyle {
		atIdx := strings.Index(rawUrl, "@")
		colonIdx := strings.Index(rawUrl, ":")
		host := rawUrl[atIdx+1 : colonIdx]
		path := strings.TrimSuffix(rawUrl[colonIdx+1:], ".git")
		return "https://" + host + "/" + path
	}

	sanitized := stripGitCredentials(rawUrl, scpStyle)

	u, err := url.Parse(sanitized)
	if err != nil {
		return sanitized
	}

	u.User = nil

	switch u.Scheme {
	case "ssh", "git+ssh", "ssh+git":
		u.Scheme = "https"
		// Strip SSH port — it's protocol-specific (e.g., 22, 7999) and doesn't map
		// to the HTTPS port. HTTP/HTTPS ports are preserved in their respective cases
		// because they represent the actual service port for that protocol.
		u.Host = u.Hostname()
		u.Path = strings.TrimSuffix(u.Path, ".git")
		return u.String()
	case "git", "http", "git+http":
		u.Scheme = "https"
		u.Path = strings.TrimSuffix(u.Path, ".git")
		return u.String()
	case "https", "git+https":
		u.Scheme = "https"
		u.Path = strings.TrimSuffix(u.Path, ".git")
		return u.String()
	default:
		return sanitized
	}
}

// isSCPStyle returns true if the URL uses SCP-style syntax (e.g., git@github.com:org/repo.git).
// Detects user@host:path patterns without a scheme prefix ("://"), where userinfo
// appears before the host/path separator ":".
func isSCPStyle(rawUrl string) bool {
	if strings.Contains(rawUrl, "://") {
		return false
	}

	atIdx := strings.Index(rawUrl, "@")
	colonIdx := strings.Index(rawUrl, ":")

	return atIdx >= 0 && colonIdx >= 0 && atIdx < colonIdx
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
