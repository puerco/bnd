// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

const SigstorePublicGoodBaseURL = "https://tuf-repo-cdn.sigstore.dev"

type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

type VerificationOptions struct {
	TufRootURL       string
	TufRootPath      string
	Fetcher          fetcher.Fetcher
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
	TufRootURL:       SigstorePublicGoodBaseURL,
	TufRootPath:      "",
	Fetcher:          defaultfetcher(),
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

// bundleVerifier is the default implementation of the bundle verifier
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
	data, err := bv.GetTufRoot(opts)
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
		"",  // Issuer
		"*", // issuerRegex
		"",  // SAN
		"*", // SAN value
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

// GetTufRoot fetches the trusted root from the configured URL or from
// the sigstore public instance.
func (bv *bundleVerifier) GetTufRoot(opts *VerificationOptions) ([]byte, error) {
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

	data, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("fetching TUF root data: %w", err)
	}

	return data, nil
}

// defaultfetcher
func defaultfetcher() fetcher.Fetcher {
	f := fetcher.DefaultFetcher{}
	f.SetHTTPUserAgent("bind/v1.0.0")
	return &f
}
