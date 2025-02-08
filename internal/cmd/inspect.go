// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/bnd/pkg/bundle"
	ampelb "github.com/puerco/ampel/pkg/formats/envelope/bundle"
	"github.com/spf13/cobra"
)

type inspectOptions struct {
	bundleOptions
}

// Validates the options in context with arguments
func (o *inspectOptions) Validate() error {
	return errors.Join(
		o.bundleOptions.Validate(),
	)
}

func (o *inspectOptions) AddFlags(cmd *cobra.Command) {
	o.bundleOptions.AddFlags(cmd)
}

func addInspect(parentCmd *cobra.Command) {
	opts := inspectOptions{}
	extractCmd := &cobra.Command{
		Short: "prints useful information about a bundle",
		Long: fmt.Sprintf(`
🥨 %s inspect:  Inspect the contents of bundled attestations

This command is a work in progress. For now it just prints minimal
data about the bundle.

		`, appname),
		Use:               "inspect",
		Example:           fmt.Sprintf("%s inspect bundle.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.bundleOptions.Path != "" && opts.bundleOptions.Path != args[0] {
				return errors.New("bundle paths specified twice (as argument and flag)")
			}
			if len(args) > 0 {
				opts.bundleOptions.Path = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			reader, closer, err := opts.OpenBundle()
			if err != nil {
				return fmt.Errorf("opening bundle: %w", err)
			}
			defer closer()

			tool := bundle.NewTool()

			envelope, err := tool.ParseBundle(reader)
			if err != nil {
				return fmt.Errorf("parsing bundle: %w", err)
			}

			att, err := tool.ExtractAttestation(envelope)
			if err != nil {
				return fmt.Errorf("unable to extract attestation from bundle")
			}

			mediatype := "unknown"
			if bndl, ok := envelope.(*ampelb.Envelope); ok {
				mediatype = bndl.GetMediaType()
			}

			fmt.Println("\nBundle Details:")
			fmt.Println("---------------")
			fmt.Printf("Bundle media type: %s\n", mediatype)
			fmt.Printf("Attestation predicate: %s\n", att.GetPredicateType())
			fmt.Println("")
			return nil
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}
