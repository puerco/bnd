// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// BundleVerifier abstracts the verification implementation to make it easy to
// mock for testing.
type BundleVerifier interface {
	OpenBundle(string) (*bundle.Bundle, error)
	BuildSigstoreVerifier(*VerificationOptions) (VerifyCapable, error)
	RunVerification(VerifyCapable, *bundle.Bundle) (*verify.VerificationResult, error)
}

// bundleVerifier implements the BundleVerifier interface.
type bundleVerifier struct{}

// OpenBundle opens a bundle file
func (bv *bundleVerifier) OpenBundle(path string) (*bundle.Bundle, error) {
	b, err := bundle.LoadJSONFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("opening path: %w", err)
	}
	return b, nil
}

// BuildSigstoreVerifier creates a configured sigstore verifier from the
// configured options
// TODO(puerco): Abstract the returned verifier
func (bv *bundleVerifier) BuildSigstoreVerifier(opts *VerificationOptions) (VerifyCapable, error) {
	trustedMaterial, err := bv.assembleTrustedMaterial(opts)
	if len(trustedMaterial) == 0 {
		return nil, errors.New("no trusted material assembled")
	}

	// Create the verifier
	sigstoreVerifier, err := verify.NewSignedEntityVerifier(trustedMaterial, bv.buildVerifierConfig(opts)...)
	if err != nil {
		return nil, fmt.Errorf("building sigstore verifier: %w", err)
	}
	return sigstoreVerifier, nil
}

func (bv *bundleVerifier) assembleTrustedMaterial(opts *VerificationOptions) (root.TrustedMaterialCollection, error) {
	var trustedMaterial = make(root.TrustedMaterialCollection, 0)

	// Fetch the trusted root data
	data, err := GetTufRoot(&opts.BindTufOptions)
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, err
	}
	trustedMaterial = append(trustedMaterial, trustedRoot)

	return trustedMaterial, nil
}

// buildVerifierConfig creates a verifier configuration from an options set
func (bv *bundleVerifier) buildVerifierConfig(opts *VerificationOptions) []verify.VerifierOption {
	config := []verify.VerifierOption{}

	if opts.RequireCTlog {
		config = append(config, verify.WithSignedCertificateTimestamps(1))
	}

	if opts.RequireTimestamp {
		config = append(config, verify.WithObserverTimestamps(1))
	}

	if opts.RequireTlog {
		config = append(config, verify.WithTransparencyLog(1))
	}

	return config
}

// RunVerification verifies an artifact using the provided verifier
func (bv *bundleVerifier) RunVerification(sigstoreVerifier VerifyCapable, bndl *bundle.Bundle) (*verify.VerificationResult, error) {
	dsse := bndl.GetDsseEnvelope()
	if dsse == nil {
		return nil, fmt.Errorf("bundle does not wrap a DSSE envelope")
	}

	if dsse.GetPayload() == nil {
		return nil, fmt.Errorf("unable to extract payload from DSSE envelope")
	}

	identityPolicies := []verify.PolicyOption{}

	// TODO(puerco): Wire these in from options
	expectedIdentity, err := verify.NewShortCertificateIdentity(
		"",    // Issuer
		`\S*`, // issuerRegex
		"",    // SAN
		`\S*`, // SAN value
	)
	if err != nil {
		return nil, fmt.Errorf("creating expected identity: %w", err)
	}
	identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(expectedIdentity))

	rdr := bytes.NewReader(dsse.GetPayload())
	res, err := sigstoreVerifier.Verify(bndl, verify.NewPolicy(verify.WithArtifact(rdr), identityPolicies...))
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	return res, nil
}
