package git

import (
	"fmt"

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

func CommitHashFromDir(inputDir string) (string, error) {
	repo, _, err := RepoFromDir(inputDir)
	if err != nil {
		return "", err
	}
	ref, err := repo.Head()
	if err != nil {
		return "", err
	}
	return ref.Hash().String(), nil
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
