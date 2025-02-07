// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// BindTufOptions captures the TUF options handled by bind
type BindTufOptions struct {
	Fetcher     fetcher.Fetcher
	TufRootPath string
	TufRootURL  string
}

// GetTufClient returns a TUF client configured with the options
func GetTufClient(opts *BindTufOptions) (*tuf.Client, error) {
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
func GetTufRoot(opts *BindTufOptions) ([]byte, error) {
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
