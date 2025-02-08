// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bnd

type VerificationOptions struct {
	TufOptions
	ArtifactDigest      string
	ArtifactDigestAlgo  string
	ExpectedIssuer      string
	ExpectedIssuerRegex string
	ExpectedSan         string
	ExpectedSanRegex    string
	SkipIdentityCheck   bool
	RequireCTlog        bool
	RequireTimestamp    bool
	RequireTlog         bool
}

var DefaultVerifierOptions = VerificationOptions{
	TufOptions: TufOptions{
		TufRootURL:  SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     defaultfetcher(),
	},
	ArtifactDigestAlgo: "sha256",
	RequireCTlog:       true,
	RequireTimestamp:   true,
	RequireTlog:        true,
}
