// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bnd

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

const SigstorePublicGoodBaseURL = "https://tuf-repo-cdn.sigstore.dev"

// TufOptions captures the TUF options handled by bind
type TufOptions struct {
	Fetcher     fetcher.Fetcher
	TufRootPath string
	TufRootURL  string
}

// GetTufClient returns a TUF client configured with the options
func GetTufClient(opts *TufOptions) (*tuf.Client, error) {
	// Build the TUF client:
	tufOpts := tuf.DefaultOptions()
	tufOpts.RepositoryBaseURL = SigstorePublicGoodBaseURL
	tufOpts.Fetcher = defaultfetcher()

	if opts.Fetcher != nil {
		tufOpts.Fetcher = opts.Fetcher
	}

	if opts.TufRootURL != "" {
		tufOpts.RepositoryBaseURL = opts.TufRootURL
	}

	client, err := tuf.New(tufOpts)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}
	return client, nil
}

// GetTufRoot fetches the trusted root from the configured URL or from
// the sigstore public instance.
func GetTufRoot(opts *TufOptions) ([]byte, error) {
	client, err := GetTufClient(opts)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}

	data, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("fetching TUF root data: %w", err)
	}

	return data, nil
}

// defaultfetcher returns a default TUF fetcher configured with the bind UA
func defaultfetcher() fetcher.Fetcher {
	f := fetcher.DefaultFetcher{}
	f.SetHTTPUserAgent("bind/v1.0.0")
	return &f
}
