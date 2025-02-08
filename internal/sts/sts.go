// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"

	"github.com/carabiner-dev/bnd/internal/sts/providers/github"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// Ensure the provider implement
var (
	_ Provider = &github.Actions{}
)

var DefaultProviders = map[string]Provider{
	"actions": &github.Actions{},
}

type Provider interface {
	Provide(context.Context, string) (*oauthflow.OIDCIDToken, error)
}
