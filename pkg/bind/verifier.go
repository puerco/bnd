// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

func NewVerifier() *Verifier {
	return &Verifier{
		Options:        DefaultVerifierOptions,
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
