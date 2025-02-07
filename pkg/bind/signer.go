// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"errors"
	"fmt"
	"io"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"google.golang.org/protobuf/encoding/protojson"
)

const GitHubTimeStamperURL = "https://timestamp.githubapp.com/api/v1/timestamp"

func NewSigner() *Signer {
	return &Signer{
		Options:      defaultSignerOptions,
		bundleSigner: &bundleSigner{},
	}
}

type Signer struct {
	Options      SignerOptions
	bundleSigner BundleSigner
}

var defaultSignerOptions = SignerOptions{
	BindTufOptions: BindTufOptions{
		TufRootURL:  SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     defaultfetcher(),
	},
	Timestamp:     true,
	AppendToRekor: true,

	OidcRedirectURL: "http://localhost:0/auth/callback",
	OidcIssuer:      "https://oauth2.sigstore.dev/auth",
	OidcClientID:    "sigstore",
}

// SignerOptions
type SignerOptions struct {
	BindTufOptions
	Token         *oauthflow.OIDCIDToken
	Timestamp     bool
	AppendToRekor bool

	// OidcRedirectURL defines the URL that the browser will redirect to.
	// if the port is set to 0, bind will randomizr it to a high number
	// port before starting the OIDC flow.
	OidcRedirectURL  string
	OidcIssuer       string
	OidcClientID     string
	OidcClientSecret string
}

func (so *SignerOptions) Validate() error {
	errs := []error{}
	if so.OidcIssuer == "" {
		errs = append(errs, errors.New("OIDC issuer not set"))
	}

	if so.OidcClientID == "" {
		errs = append(errs, errors.New("OIDC client not set"))
	}

	if so.OidcRedirectURL == "" {
		errs = append(errs, errors.New("OIDC redirect URL not set"))
	}
	// opts.OidcClientSecret

	return errors.Join(errs...)
}

// WriteBundle writes the bundle JSON to
func (s *Signer) WriteBundle(bndl *v1.Bundle, w io.Writer) error {
	bundleJSON, err := protojson.Marshal(bndl)
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}

	if _, err := w.Write(bundleJSON); err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}

	return nil
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (s *Signer) SignStatement(data []byte) (*v1.Bundle, error) {
	// Verify the defined options:
	if err := s.Options.Validate(); err != nil {
		return nil, err
	}
	// check statement (not emtpy is it intoto)
	if err := s.bundleSigner.VerifyContent(&s.Options, data); err != nil {
		return nil, fmt.Errorf("verifying content: %w", err)
	}

	// Wrap the attestation in its DSSE envelope
	content := s.bundleSigner.WrapStatement(data)

	// Get(or generate) the public key
	keypair, err := s.bundleSigner.GetKeyPair(&s.Options)
	if err != nil {
		return nil, err
	}

	// Get the ID token
	if err := s.bundleSigner.GetOidcToken(&s.Options); err != nil {
		return nil, fmt.Errorf("getting ID token: %w", err)
	}

	// Generate the signer options
	bundleSignerOption, err := s.bundleSigner.BuildSigstoreSignerOptions(&s.Options)
	if err != nil {
		return nil, fmt.Errorf("building options: %w", err)
	}

	bndl, err := s.bundleSigner.SignBundle(content, keypair, *bundleSignerOption)
	if err != nil {
		return nil, fmt.Errorf("singing statement: %w", err)
	}
	return bndl, nil
}

type BundleSigner interface {
	VerifyContent(*SignerOptions, []byte) error
	WrapStatement([]byte) *sign.DSSEData
	GetKeyPair(*SignerOptions) (*sign.EphemeralKeypair, error)
	GetOidcToken(*SignerOptions) error
	BuildSigstoreSignerOptions(*SignerOptions) (*sign.BundleOptions, error)
	SignBundle(content sign.Content, keypair sign.Keypair, opts sign.BundleOptions) (*v1.Bundle, error)
}
