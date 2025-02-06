// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/carabiner-dev/bind/pkg/bind"
	"github.com/spf13/cobra"
)

type sigstoreOptions struct {
	TufRootURL  string
	TufRootPath string
}

func (so *sigstoreOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&so.TufRootURL, "trust-root", bind.SigstorePublicGoodBaseURL,
		"Base URL to fetch the trusted TUF roots",
	)

	cmd.PersistentFlags().StringVar(
		&so.TufRootPath, "trust-root-path", "",
		"Path to an already downloaded TUF trust root JSON file",
	)
}

func (so *sigstoreOptions) Validate() error {
	var errs = []error{}
	if so.TufRootURL != "" {
		if _, err := url.Parse(so.TufRootURL); err != nil {
			errs = append(errs, fmt.Errorf("parsing tuf URL: %w", err))
		}

	}
	return errors.Join(errs...)
}
