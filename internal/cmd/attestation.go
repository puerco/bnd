// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/bind/pkg/bundle"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

type attestationOptions struct {
	Sign bool
}

// Validates the options in context with arguments
func (ao *attestationOptions) Validate() error {
	return nil
}

func (o *attestationOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(
		&o.Sign,
		"sign",
		"s",
		true,
		"bind an unsigned in-toto attestation",
	)
}

func addAttestation(parentCmd *cobra.Command) {
	opts := attestationOptions{}
	attCmd := &cobra.Command{
		Short:             fmt.Sprintf("%s attestation: binds an attestation into a signed bundle", appname),
		Use:               "attestation",
		Example:           fmt.Sprintf("%s attestation file.intoto.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			ctx := context.Background()
			if len(args) == 0 {
				return fmt.Errorf("no attestation file specified")
			}

			var f io.Reader
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("opening attestation file")
			}

			attData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading attestation data: %s", err)
			}

			signer := bundle.NewSigner()
			bundle, err := signer.SignAndBind(ctx, attData)
			if err != nil {
				return fmt.Errorf("binding attestation: %w", err)
			}

			o := os.Stdout

			// enc := json.NewEncoder(o)
			data, err := protojson.Marshal(bundle)
			if err != nil {
				return fmt.Errorf("marshaling bundle: %w", err)
			}

			if _, err := o.Write(data); err != nil {
				return fmt.Errorf("writing bundle data: %w", err)
			}

			return nil
		},
	}
	opts.AddFlags(attCmd)
	parentCmd.AddCommand(attCmd)
}
