// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/bind/pkg/bundle"
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
		Short:             "prints useful information about a bundle",
		Use:               "inspect",
		Example:           fmt.Sprintf("%s inspect bundle.json ", appname),
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

			att, err := tool.ExtractAttestation(b)
			if err != nil {
				return fmt.Errorf("unable to extract attestation from bundle")
			}

			fmt.Println("\nBundle Details:")
			fmt.Println("---------------")
			fmt.Printf("Bundle media type: %s\n", b.MediaType)
			fmt.Printf("Attestation predicate: %s\n", att.PredicateType)
			fmt.Println("")
			return nil
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}
