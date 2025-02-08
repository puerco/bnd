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
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/puerco/ampel/pkg/formats/statement/intoto"
)

type Tool struct{}

func NewTool() *Tool {
	return &Tool{}
}

// Parse reades the budle data from reader r and decodes it into
func (t *Tool) ParseBundle(r io.Reader) (*protobundle.Bundle, error) {
	var bndl sbundle.Bundle
	bndl.Bundle = new(protobundle.Bundle)

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading bundle data: %w", err)
	}
	if err := bndl.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("unmarshalling bundle JSON: %w", err)
	}
	return bndl.Bundle, nil
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
	return string(attestation.PredicateType), nil
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
	p := intoto.Parser{}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading attestation data")
	}
	statement, err := p.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing statement: %w", err)
	}
	return statement.(*intoto.Statement), nil
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
