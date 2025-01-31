// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	fulcioapi "github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// internal/git

type CertSignerVerifier struct {
	signature.SignerVerifier

	Cert  []byte
	Chain []byte
}

func sign() (any, error) {
	ctx := context.Background()

	var privateKey crypto.PrivateKey
	var cert, certChain []byte

	sv, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("error creating SignerVerifier: %w", err)
	}

	csv := &CertSignerVerifier{
		SignerVerifier: sv,
		Cert:           cert,
		Chain:          certChain,
	}

	commitSig, err := sv.SignMessage(bytes.NewBufferString("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"))
	if err != nil {
		return nil, fmt.Errorf("error signing commit hash: %w", err)
	}

	// Publish entry to rekor
	entry, err := WriteTlog(ctx, []byte("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"), commitSig, resp.Cert)
	if err != nil {
		return nil, fmt.Errorf("error uploading tlog (commit): %w", err)
	}

}

// WriteTlogWrites to rekor
func WriteTlog(ctx context.Context, message, signature []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	// Marshall the cert
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}

	// cimpute the messagechecksum
	checkSum := sha256.New()
	if _, err := checkSum.Write(message); err != nil {
		return nil, err
	}

	// client, err := rekor.NewClient("")
	client, err := rekor.GetRekorClient("https://rekor.sigstore.dev", o.clientOpts...)
	if err != nil {
		return nil, err
	}

	return cosign.TLogUpload(ctx, client, signature, checkSum, pem)
}

// Extract the certificate
func GetCert(priv crypto.Signer) (*fulcioapi.CertificateResponse, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	tok, err := oauthflow.OIDConnect(
		c.oidc.Issuer, c.oidc.ClientID, c.oidc.ClientSecret, c.oidc.RedirectURL, c.oidc.TokenGetter,
	)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := priv.Sign(rand.Reader, h[:], nil)
	if err != nil {
		return nil, err
	}

	cr := fulcioapi.CertificateRequest{
		PublicKey: fulcioapi.Key{
			Algorithm: keyAlgorithm(priv),
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return c.SigningCert(cr, tok.RawString)
}
