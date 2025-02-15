// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bnd

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/carabiner-dev/bnd/internal/sts"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/term"
)

// BundleSigner abstracts the signer implementation to make it easy to mock
type BundleSigner interface {
	VerifyContent(*SignerOptions, []byte) error
	WrapStatement([]byte) *sign.DSSEData
	GetKeyPair(*SignerOptions) (*sign.EphemeralKeypair, error)
	GetAmbienTokens(*SignerOptions) error
	GetOidcToken(*SignerOptions) error
	BuildSigstoreSignerOptions(*SignerOptions) (*sign.BundleOptions, error)
	SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*v1.Bundle, error)
}

// bundleSigner implements the BundleSigner interface for the signer
type bundleSigner struct{}

func (bs *bundleSigner) WrapStatement(data []byte) *sign.DSSEData {
	content := &sign.DSSEData{
		Data:        data,
		PayloadType: "application/vnd.in-toto+json",
	}
	return content
}

// VerifyContent checka that the attestation is in good shape to sign
func (bs *bundleSigner) VerifyContent(*SignerOptions, []byte) error {
	// TODO: WEnsure this is righr
	return nil
}

// GetKeyPair calls the configured key generator and returns
// a keypair which will be used to sign
func (bs *bundleSigner) GetKeyPair(opts *SignerOptions) (*sign.EphemeralKeypair, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair")
	}

	// Extract the PEM data to ensure it worked
	_, err = keypair.GetPublicKeyPem()
	// TODO(we clouidl log or store the public key)
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}

	return keypair, nil
}

func (bs *bundleSigner) BuildSigstoreSignerOptions(opts *SignerOptions) (*sign.BundleOptions, error) {
	if opts.Token == nil {
		return nil, fmt.Errorf("no OIDC token set")
	}
	// bundleOptions is the options set to configure the sigstore signer
	bundleOptions := sign.BundleOptions{}
	tufClient, err := GetTufClient(&opts.TufOptions)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}

	// Get and configure the TUF root:
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetching TUF root: %w", err)
	}
	bundleOptions.TrustedRoot = trustedRoot

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("getting signing config from TUF")
	}

	// Config fuilcio
	fulcioOpts := &sign.FulcioOptions{
		BaseURL: signingConfig.FulcioCertificateAuthorityURL(),
		Timeout: 30 * time.Second,
		Retries: 1,
	}

	bundleOptions.CertificateProvider = sign.NewFulcio(fulcioOpts)
	bundleOptions.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: opts.Token.RawString,
	}

	if opts.Timestamp {
		for _, tsaURL := range signingConfig.TimestampAuthorityURLs() {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL,
				Timeout: 30 * time.Second,
				Retries: 1,
			}
			bundleOptions.TimestampAuthorities = append(
				bundleOptions.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts),
			)
		}
	}

	if opts.AppendToRekor {
		for _, rekorURL := range signingConfig.RekorLogURLs() {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL,
				Timeout: 90 * time.Second,
				Retries: 1,
			}
			bundleOptions.TransparencyLogs = append(bundleOptions.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	return &bundleOptions, nil
}

// SignBundle signs the DSSE envelop and returns the new bundle
func (bs *bundleSigner) SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*v1.Bundle, error) {
	bndl, err := sign.Bundle(content, keypair, *opts)
	if err != nil {
		return nil, fmt.Errorf("signing DSSE wrapper: %w", err)
	}

	return bndl, nil
}

func (bs *bundleSigner) GetOidcToken(opts *SignerOptions) error {
	//
	// Create the OIDC connector and choose the proper flow depending on the
	// environment.
	//
	// TODO(puerco): This needs to fetch the token from github actions
	connector := &oidcConnector{}
	switch {
	case opts.Token != nil:
		connector.flow = &oauthflow.StaticTokenGetter{RawToken: opts.Token.RawString}
	case !term.IsTerminal(0):
		connector.flow = oauthflow.NewDeviceFlowTokenGetterForIssuer(opts.OidcIssuer)
	default:
		connector.flow = oauthflow.DefaultIDTokenGetter
	}

	// Run the flow and get the access token:
	tok, err := connector.Connect(
		opts.OidcIssuer,
		opts.OidcClientID,
		opts.OidcClientSecret,
		randomizePort(opts.OidcRedirectURL),
	)
	if err != nil {
		return fmt.Errorf("running OIDC flow: %w", err)
	}

	opts.Token = tok
	return nil
}

func randomizePort(redirectURL string) string {
	p, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	rond, err := rand.Int(rand.Reader, big.NewInt(64511))
	if err != nil {
		// :(
		return ""
	}
	replace := strings.Replace(
		redirectURL, fmt.Sprintf("%s:0/", p.Hostname()), fmt.Sprintf("%s:%d/", p.Hostname(), rond.Int64()+1025), 1,
	)
	return replace
}

func (bs *bundleSigner) GetAmbienTokens(opts *SignerOptions) error {
	// If sts providers are disabled, we're done.
	if opts.DisableSTS {
		return nil
	}

	ctx := context.Background()

	for k, provider := range sts.DefaultProviders {
		token, err := provider.Provide(ctx, opts.OidcClientID)
		if err != nil {
			return fmt.Errorf("trying ambien credentials from %s: %w", k, err)
		}

		if token != nil {
			opts.Token = token
			return nil
		}
	}
	return nil
}

type oidcConnector struct {
	flow oauthflow.TokenGetter
}

func (rf *oidcConnector) Connect(urlString, clientID, secret, redirectURL string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(urlString, clientID, secret, redirectURL, rf.flow)
}
