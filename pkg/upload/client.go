// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/carabiner-dev/github"
	"github.com/sirupsen/logrus"
)

var GitHubAttestationsEndpoint = `repos/%s/%s/attestations`

func NewClient() *Client {
	return &Client{
		GitHubAPIHostname: github.DefaultAPIHostname,
	}
}

type Client struct {
	GitHubAPIHostname string
}

type uploadRequestValueParsed struct {
	Bundle preParsedBundle `json:"bundle"`
}

type preParsedBundle []byte

func (ppb preParsedBundle) MarshalJSON() ([]byte, error) {
	return ppb, nil
}

// PushFileToGithub posts an attestation to the GitHub store from a bundle
// file.
func (c *Client) PushBundleFileToGithub(org, repo, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading bundle: %w", err)
	}

	payload := uploadRequestValueParsed{
		Bundle: preParsedBundle(data),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marhsaling payload: %w", err)
	}

	logrus.Debugf("Request body: %s", string(jsonData))
	return c.pushAttestationToGitHub(org, repo, bytes.NewReader(jsonData))
}

// PushFileToGithub posts an attestation to the GitHub store from a bundle
// file.
func (c *Client) PushBundleToGithub(org, repo string, data []byte) error {
	payload := uploadRequestValueParsed{
		Bundle: preParsedBundle(data),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marhsaling payload: %w", err)
	}

	logrus.Debugf("Request body: %s", string(jsonData))
	return c.pushAttestationToGitHub(org, repo, bytes.NewReader(jsonData))
}

// pushAttestationToGitHub reads a bundle from the reader r and posts it to the
// GitHub attestation store
func (c *Client) pushAttestationToGitHub(org, repo string, r io.Reader) error {
	ghclient, err := github.NewClientWithOptions(github.Options{
		Host:        c.GitHubAPIHostname,
		TokenReader: &github.DefaultEnvTokenReader,
	})
	if err != nil {
		return fmt.Errorf("creating github client: %w", err)
	}

	// Cal the API to upload the bundle
	res, err := ghclient.Call(
		context.Background(), http.MethodPost,
		fmt.Sprintf(GitHubAttestationsEndpoint, org, repo), r,
	)
	if err != nil {
		return fmt.Errorf("uploading attestation bundle: %w", err)
	}
	defer res.Body.Close()

	logrus.Infof("Response code %d after pushing", res.StatusCode)
	return nil
}
