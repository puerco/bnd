// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"fmt"
	"os"

	gogit "github.com/go-git/go-git/v5"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-sdk/git"
)

type Components struct {
	Tool      string
	Transport string
	Hostname  string
	RepoPath  string
	Ref       string
	SubPath   string
}

// CloneOrOpenCommit clones a repository to a temporary file and
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
