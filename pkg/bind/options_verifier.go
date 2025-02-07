// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

type VerificationOptions struct {
	BindTufOptions
	RequireCTlog     bool
	RequireTimestamp bool
	RequireTlog      bool
}

var DefaultVerifierOptions = VerificationOptions{
	BindTufOptions: BindTufOptions{
		TufRootURL:  SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     defaultfetcher(),
	},
	RequireCTlog:     true,
	RequireTimestamp: true,
	RequireTlog:      true,
}
