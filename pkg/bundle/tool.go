// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	// "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"

	//"github.com/sigstore/rekor/pkg/types/intoto"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Tool struct{}

func NewTool() *Tool {
	return &Tool{}
}

// Parse reades the budle data from reader r and decodes it into
func (t *Tool) ParseBundle(r io.Reader) (*protobundle.Bundle, error) {
	var bundle = &protobundle.Bundle{
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:                   &protobundle.VerificationMaterial_X509CertificateChain{},
			TlogEntries:               []*v1.TransparencyLogEntry{},
			TimestampVerificationData: &protobundle.TimestampVerificationData{},
		},
		Content: &protobundle.Bundle_DsseEnvelope{},
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(bundle); err != nil {
		return nil, fmt.Errorf("deconding bundle: %w", err)
	}
	return bundle, nil
}

// getBundleContentIfDSSE returns the bundle contents if it is wrapped in a DSSE
// envelope. Returns nil in any other case.
func getBundleContentIfDSSE(bundle *protobundle.Bundle) *protobundle.Bundle_DsseEnvelope {
	if bundle.Content == nil {
		return nil
	}
	if dsse, ok := bundle.Content.(*protobundle.Bundle_DsseEnvelope); ok {
		return dsse
	}

	return nil
}

// ExtractPredicateJSON is akin to ExtractPredicate but returns the predicated
// marshalled as JSON
func (t *Tool) ExtractPredicateJSON(bundle *protobundle.Bundle) ([]byte, error) {
	pred, err := t.ExtractPredicate(bundle)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pred); err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}
	return b.Bytes(), nil
}

// ExtractPredicateType returns a string with the attestation predicate type
func (t *Tool) ExtractPredicateType(bundle *protobundle.Bundle) (string, error) {
	attestation, err := t.ExtractAttestation(bundle)
	if err != nil {
		return "", fmt.Errorf("extracting attestation: %w", err)
	}
	return attestation.PredicateType, nil
}

// ExtractPredicate returns the attestation predicate data
func (t *Tool) ExtractPredicate(bundle *protobundle.Bundle) (any, error) {
	attestation, err := t.ExtractAttestation(bundle)
	if err != nil {
		return nil, fmt.Errorf("extracting attestation: %w", err)
	}
	return attestation.Predicate, nil
}

// ParseAttestation reads an attestation from the Reader r and
func (t *Tool) ParseAttestation(r io.Reader) (*intoto.Statement, error) {
	attestation := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{},
	}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(attestation); err != nil {
		return nil, fmt.Errorf("decoding attestation json: %w", err)
	}
	return attestation, nil
}

// ExtractAttestation returns a strut with the data decoded from the bundle
// contents JSON.
func (t *Tool) ExtractAttestation(bundle *protobundle.Bundle) (*intoto.Statement, error) {
	attestationData, err := t.ExtractAttestationJSON(bundle)
	if err != nil {
		return nil, fmt.Errorf("extracting attestation: %w", err)
	}

	var b bytes.Buffer
	if _, err := b.Write(attestationData); err != nil {
		return nil, fmt.Errorf("buffering attestation data: %w", err)
	}

	attestation, err := t.ParseAttestation(&b)
	if err != nil {
		return nil, fmt.Errorf("parsing attestation json: %w", err)
	}
	return attestation, nil
}

// ExtractAttestationJSON returns the attestation JSON enclosed in the bundle
func (t *Tool) ExtractAttestationJSON(bundle *protobundle.Bundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("attempt to extract predicate from nil bundle")
	}
	dssePayload := getBundleContentIfDSSE(bundle)
	if dssePayload == nil || dssePayload.DsseEnvelope == nil {
		return nil, fmt.Errorf("bundle has no DSSE payload")
	}

	return dssePayload.DsseEnvelope.Payload, nil
}

type VerificationResults struct{}

func (t *Tool) Verify(*protobundle.Bundle) (bool, *VerificationResults, error) {
	return false, nil, nil
}
