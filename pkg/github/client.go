// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

type Client struct {
}

func New() *Client {
	return &Client{}
}

func (c *Client) Call(ctx context.Context) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN env var not set ")
	}
	oauthClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	))
	client := github.NewClient(oauthClient)

	// att, err := os.Open("/home/urbano/Projects/bind/test.bundle.json")
	attData, err := os.ReadFile("/home/urbano/Projects/bind/test.bundle.json")
	if err != nil {
		return fmt.Errorf("reading bundle file: %w", err)
	}

	vals := url.Values{}
	vals.Add("bundle", string(attData))
	res, err := client.Client().PostForm(
		// "https://api.github.com/repos/puerco/tests/attestations/sha256%3A62f2924a0bc60cc14ddb236044486c221766a0f86480446bc36f3d7824d51aa6",
		// "https://api.github.com/repos/puerco/tests/attestations/sha256:62f2924a0bc60cc14ddb236044486c221766a0f86480446bc36f3d7824d51aa6",
		"https://api.github.com/repos/puerco/lab/attestations", vals,

		// /repos/{owner}/{repo}/attestations
		//"application/vnd.dev.sigstore.bundle+json;version=0.2", att,
		//"application/vnd.dev.sigstore.bundle.v0.2+json", att,
		//"application/json; charset=utf-8", att,
	)
	if err != nil {
		return fmt.Errorf("errror posting attestion: %w", err)
	}
	fmt.Printf("No error, pero esto:\n%+v", res)
	b, _ := io.ReadAll(res.Body)
	fmt.Printf("No error, pero esto:\n%+v", string(b))
	/*

		user, _, err := client.Users.Get(ctx, "")
		if err != nil {
			return fmt.Errorf("client.Users.Get() failed: %w", err)

		}
		d, err := json.MarshalIndent(user, "", "  ")
		if err != nil {
			return fmt.Errorf("json.MarshlIndent() failed: %w", err)
		}
		fmt.Printf("User:\n%s\n", string(d))
	*/
	return nil
}
