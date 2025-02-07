// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"fmt"
	"os"

	gogit "github.com/go-git/go-git/v5"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-sdk/git"
	"sigs.k8s.io/release-utils/command"
)

type Components struct {
	Tool      string
	Transport string
	Hostname  string
	RepoPath  string
	Ref       string
	SubPath   string
}

// CloneOrOpenCommit clones a repository at a specified reference into a
// temporary directory and returns the path, a cleaner function or an error
// if cloning fails.
func CloneOrOpenCommit(repoURL, commit string) (string, func() error, error) {
	var existingDir = ""
	repo, err := git.CloneOrOpenRepo("", repoURL, false, false, &gogit.CloneOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("cloning repository: %w", err)
	}

	var tmp = ""
	if existingDir == "" {
		tmp = repo.Dir()
		logrus.Debugf("cloned repo to %s", repoURL)
	}

	// Only create the cleaner func if using a tmp path
	var cleaner = func() error {
		if tmp != "" {
			return os.RemoveAll(tmp)
		}
		return nil
	}

	if commit == "" {
		return repo.Dir(), cleaner, nil
	}

	if err := repo.Checkout(commit); err != nil {
		return "", cleaner, fmt.Errorf("cloning repo: %w", err)
	}

	return repo.Dir(), cleaner, nil
}

type RepositoryDetails struct {
	CommitSHA string
	Tag       string
	RepoURL   string
}

func GetRepositoryDetails(path string) (*RepositoryDetails, error) {
	details := &RepositoryDetails{}
	res, err := command.NewWithWorkDir(path, "git", "remote", "-v").RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("running git to get remotes: %w", err)
	}
	details.RepoURL = res.OutputTrimNL()

	res, err = command.NewWithWorkDir(path, "git", "rev-parse", "HEAD").RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("running git to get revision: %w", err)
	}
	details.CommitSHA = res.OutputTrimNL()

	res, err = command.NewWithWorkDir(path, "git", "tag", "--points-at", "HEAD").RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("running git to get revision: %w", err)
	}
	details.Tag = res.OutputTrimNL()

	return details, nil
}
