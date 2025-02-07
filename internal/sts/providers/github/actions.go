// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package github implements a client to requesta short lived token
// from github actions.
//
// Shamelessly stolen from https://pkg.go.dev/github.com/sigstore/cosign/v2/pkg/providers/github
// but adapted here to avoid pulling down all sigstore/cosign and, thus, the world.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	VariableGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	VariableGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

type Actions struct{}

// Provide requests a token from github actions
func (actions *Actions) Provide(ctx context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	// Get the request URL from the environment vars
	url := os.Getenv(VariableGitHubRequestURL)
	if url == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s&audience=%s", url, audience), nil)
	if err != nil {
		return nil, err
	}

	// May be replaced by a different client if we hit HTTP_1_1_REQUIRED.
	client := http.DefaultClient

	// Retry up to 3 times.
	for i := 0; ; i++ {
		req.Header.Add("Authorization", "bearer "+os.Getenv(VariableGitHubRequestToken))
		resp, err := client.Do(req)
		if err != nil {
			if i == 2 {
				return nil, err
			}

			// This error isn't exposed by net/http, and retrying this with the
			// DefaultClient will fail because it will just use HTTP2 again.
			// I don't know why go doesn't do this for us.
			if strings.Contains(err.Error(), "HTTP_1_1_REQUIRED") {
				http1transport := http.DefaultTransport.(*http.Transport).Clone()
				http1transport.ForceAttemptHTTP2 = false

				client = &http.Client{
					Transport: http1transport,
				}
			}

			fmt.Fprintf(os.Stderr, "error fetching GitHub OIDC token (will retry): %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		defer resp.Body.Close()

		var payload struct {
			Value string `json:"value"`
		}
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&payload); err != nil {
			return nil, err
		}

		token := &oauthflow.OIDCIDToken{
			RawString: payload.Value,
			Subject:   "", // TODO(puerco): Perhaps parse and populate here
		}

		return token, nil
	}
}
