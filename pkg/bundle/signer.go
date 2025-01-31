// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	dsseSigner "github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type Signer struct{}

func NewSigner() *Signer {
	return &Signer{}
}

// SignAndBind creates a sigstore bundle by signing an attestation and
// grouping it with all the data needed to verify it. The signing operation
// is recorded in sigstore's transparency log and the inclusion proof
// is added to the bundle.
//
// Warning: This is a temporary function which will be split into more
// components.
func (s *Signer) SignAndBind(ctx context.Context, attData []byte) (*protobundle.Bundle, error) {
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", options.KeyOpts{
		FulcioURL:            "https://fulcio.sigstore.dev",
		RekorURL:             "https://rekor.sigstore.dev",
		OIDCIssuer:           "https://oauth2.sigstore.dev/auth",
		OIDCClientID:         "sigstore",
		OIDCDisableProviders: false,
		SkipConfirmation:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	// Create the dsse signer
	wrapped := dsseSigner.WrapSigner(sv, types.IntotoPayloadType)

	payload := attData

	// Sign!
	dsseWrapped, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "signing")
	}

	// Decode the dsse wrapper
	dsseEnvelope := &dsse.Envelope{}
	if err := json.Unmarshal(dsseWrapped, dsseEnvelope); err != nil {
		return nil, fmt.Errorf("decoding DSSE envelope: %w", err)
	}

	// Aqui se fue el timestamp, hay que regresarlo

	// Get the public key
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return nil, err
	}

	rekorClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		return nil, err
	}

	entry, err := cosign.TLogUploadDSSEEnvelope(ctx, rekorClient, dsseWrapped, rekorBytes)
	if err != nil {
		return nil, err
	}

	// Transfer the signatures from the dsse envelope
	sigs := []*protodsse.Signature{}
	for _, s := range dsseEnvelope.Signatures {
		sigs = append(sigs, &protodsse.Signature{
			Sig:   []byte(s.Sig),
			Keyid: s.KeyID,
		})
	}

	envelope := protodsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  sigs,
	}
	hashesArray := [][]byte{}
	for _, h := range entry.Verification.InclusionProof.Hashes {
		hashesArray = append(hashesArray, []byte(h))
	}

	canonBody, err := base64.StdEncoding.DecodeString(entry.Body.(string))
	if err != nil {
		return nil, fmt.Errorf("decoding rekor entry body: %w", err)
	}

	// Un marchal the rekord
	rekord := &models.DSSE{
		Spec: models.DSSEV001Schema{},
	}

	if err := json.Unmarshal(canonBody, rekord); err != nil {
		return nil, fmt.Errorf("unmarshalling rekord: %w", err)
	}
	mt, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		return nil, fmt.Errorf("building mediatype string: %s", err)
	}
	bundle := &protobundle.Bundle{
		// MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
		MediaType: mt,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{
						{
							RawBytes: sv.Cert,
						},
						{
							RawBytes: sv.Chain,
						},
					},
				},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{
				{
					LogIndex: *entry.LogIndex,
					LogId: &protocommon.LogId{
						KeyId: []byte(*entry.LogID),
					},
					KindVersion: &protorekor.KindVersion{
						Kind:    rekord.Kind(),
						Version: *rekord.APIVersion,
					},
					IntegratedTime: *entry.IntegratedTime,
					InclusionPromise: &protorekor.InclusionPromise{
						SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
					},
					InclusionProof: &protorekor.InclusionProof{
						LogIndex: *entry.Verification.InclusionProof.LogIndex,
						RootHash: []byte(*entry.Verification.InclusionProof.RootHash),
						TreeSize: *entry.Verification.InclusionProof.TreeSize,
						Hashes:   hashesArray,
						Checkpoint: &protorekor.Checkpoint{
							Envelope: *entry.Verification.InclusionProof.Checkpoint,
						},
					},
					CanonicalizedBody: canonBody,
				},
			},
			TimestampVerificationData: &protobundle.TimestampVerificationData{},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &envelope,
		},
	}

	return bundle, nil
}
