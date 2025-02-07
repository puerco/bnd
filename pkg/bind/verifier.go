// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

const SigstorePublicGoodBaseURL = "https://tuf-repo-cdn.sigstore.dev"

type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

type VerificationOptions struct {
	BindTufOptions
	RequireCTlog     bool
	RequireTimestamp bool
	RequireTlog      bool
}

type BundleVerifier interface {
	OpenBundle(string) (*bundle.Bundle, error)
	BuildSigstoreVerifier(*VerificationOptions) (VerifyCapable, error)
	RunVerification(VerifyCapable, *bundle.Bundle) (*verify.VerificationResult, error)
}

var defaultVerifierOptions = VerificationOptions{
	BindTufOptions: BindTufOptions{
		TufRootURL:  SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     defaultfetcher(),
	},
	RequireCTlog:     true,
	RequireTimestamp: true,
	RequireTlog:      true,
}

func NewVerifier() *Verifier {
	return &Verifier{
		Options:        VerificationOptions{},
		bundleVerifier: &bundleVerifier{},
	}
}

type Verifier struct {
	Options        VerificationOptions
	bundleVerifier BundleVerifier
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyBundle(budlePath string) (*verify.VerificationResult, error) {
	bndl, err := v.bundleVerifier.OpenBundle(budlePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle: %w", err)
	}

	vrfr, err := v.bundleVerifier.BuildSigstoreVerifier(&v.Options)
	if err != nil {
		return nil, fmt.Errorf("creatging creating verifier: %w", err)
	}

	result, err := v.bundleVerifier.RunVerification(vrfr, bndl)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	return result, err
}

// defaultfetcher returns a default TUF fetcher configured with the bind UA
func defaultfetcher() fetcher.Fetcher {
	f := fetcher.DefaultFetcher{}
	f.SetHTTPUserAgent("bind/v1.0.0")
	return &f
}
