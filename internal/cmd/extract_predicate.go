// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/bnd/pkg/bundle"
	"github.com/spf13/cobra"
)

type extractPredOptions struct {
	outFileOptions
	bundleOptions
	TypeOnly        bool
	FromAttestation bool
}

// Validates the options in context with arguments
func (o *extractPredOptions) Validate() error {
	return errors.Join(
		o.outFileOptions.Validate(),
		o.bundleOptions.Validate(),
	)
}

func (o *extractPredOptions) AddFlags(cmd *cobra.Command) {
	o.outFileOptions.AddFlags(cmd)
	o.bundleOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&o.TypeOnly,
		"type",
		false,
		"extract only the preicate type srting",
	)

	cmd.PersistentFlags().BoolVar(
		&o.FromAttestation,
		"from-attestation",
		false,
		"treat the input file as an attestation, not a bundle",
	)
}

func addExtractPredicate(parentCmd *cobra.Command) {
	opts := extractPredOptions{}
	extractCmd := &cobra.Command{
		Short:             "extracts the attestation predicate from a bundle",
		Use:               "predicate",
		Example:           fmt.Sprintf("%s extract predicate bundle.json ", appname),
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

			out, ocloser, err := opts.OutputWriter()
			if err != nil {
				return nil
			}
			defer ocloser()

			if opts.FromAttestation {
				b, err := tool.ParseAttestation(reader)
				if err != nil {
					return err
				}
				return encodeOutputJSON(out, b)
			}

			b, err := tool.ParseBundle(reader)
			if err != nil {
				return fmt.Errorf("parsing bundle: %w", err)
			}

			if opts.TypeOnly {
				predType, err := tool.ExtractPredicateType(b)
				if err != nil {
					return fmt.Errorf("extracting predicate type: %w", err)
				}
				fmt.Fprintln(out, predType)
				return nil
			}

			pred, err := tool.ExtractPredicate(b)
			if err != nil {
				return fmt.Errorf("extracting predicate: %w", err)
			}

			return encodeOutputJSON(out, pred)
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}

func encodeOutputJSON(out io.Writer, data any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encoding predicate: %w", err)
	}
	return nil
}
