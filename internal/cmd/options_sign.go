// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/pkg/bnd"
)

type signOptions struct {
	Sign            bool
	OidcRedirectURL string
	OidcIssuer      string
	OidcClientID    string
}

func (so *signOptions) Validate() error {
	return nil
}

func (so *signOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&so.Sign, "sign", true, "trigger the signing process",
	)

	cmd.PersistentFlags().StringVar(
		&so.OidcIssuer, "oidc-issuer", bnd.DefaultSignerOptions.OidcIssuer, "OIDC issuer URL",
	)

	cmd.PersistentFlags().StringVar(
		&so.OidcRedirectURL, "oidc-redirect-url", bnd.DefaultSignerOptions.OidcRedirectURL, "Redirect URL for the OIDC interactive flow",
	)

	cmd.PersistentFlags().StringVar(
		&so.OidcClientID, "oidc-client-id", bnd.DefaultSignerOptions.OidcClientID, "Client ID to to set in token audience",
	)
}
