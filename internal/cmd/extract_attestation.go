// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/carabiner-dev/bind/pkg/bundle"
	"github.com/spf13/cobra"
)

type extractAttOptions struct {
	outFileOptions
	bundleOptions
	AsDSSE bool
}

// Validates the options in context with arguments
func (o *extractAttOptions) Validate() error {
	return errors.Join(
		o.outFileOptions.Validate(),
		o.bundleOptions.Validate(),
	)
}

func (o *extractAttOptions) AddFlags(cmd *cobra.Command) {
	o.outFileOptions.AddFlags(cmd)
	o.bundleOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&o.AsDSSE,
		"dsse",
		false,
		"output the attestation wrapped in its DSSE bundle",
	)
}

func addExtractAttestation(parentCmd *cobra.Command) {
	opts := extractAttOptions{}
	extractCmd := &cobra.Command{
		Short:             "extracts the attestation contained in a bundle",
		Use:               "attestation",
		Example:           fmt.Sprintf("%s extract attestation bundle.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.SetBundlePath(args[0]); err != nil {
					return err
				}
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			reader, closer, err := opts.OpenBundle()
			if err != nil {
				return fmt.Errorf("opening bundle: %w", err)
			}
			defer closer()

			tool := bundle.NewTool()

			b, err := tool.ParseBundle(reader)
			if err != nil {
				return fmt.Errorf("parsing bundle: %w", err)
			}

			pred, err := tool.ExtractAttestation(b)
			if err != nil {
				return fmt.Errorf("extracting predicate: %w", err)
			}

			out, ocloser, err := opts.OutputWriter()
			if err != nil {
				return nil
			}
			defer ocloser()

			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			if err := enc.Encode(pred); err != nil {
				return fmt.Errorf("encoding predicate: %w", err)
			}

			return nil
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}
