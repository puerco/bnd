// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/bind/pkg/bind"
	"github.com/spf13/cobra"
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
		&so.OidcRedirectURL, "oidc-issuer", bind.DefaultSignerOptions.OidcIssuer, "OIDC issuer URL",
	)

	cmd.PersistentFlags().StringVar(
		&so.OidcRedirectURL, "oidc-redirect-url", bind.DefaultSignerOptions.OidcRedirectURL, "Redirect URL for the OIDC interactive flow",
	)

	cmd.PersistentFlags().StringVar(
		&so.OidcClientID, "oidc-client-id", bind.DefaultSignerOptions.OidcClientID, "Client ID to to set in token audience",
	)
}
