// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/bind/pkg/bundle"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	bundleOptions
}

// Validates the options in context with arguments
func (o *verifyOptions) Validate() error {
	return errors.Join(
		o.bundleOptions.Validate(),
	)
}

func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.bundleOptions.AddFlags(cmd)
}

func addVerify(parentCmd *cobra.Command) {
	opts := verifyOptions{}
	verifyCmd := &cobra.Command{
		Short:             "Verifies a bundle signature",
		Use:               "verify",
		Example:           fmt.Sprintf("%s verify bundle.json ", appname),
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

			ok, result, err := tool.Verify(b)
			if err != nil {
				return fmt.Errorf("verifying bundle: %w", err)
			}

			if !ok {
				return fmt.Errorf("bundle verification failed")
			}

			fmt.Printf("%+v", result)
			return nil
		},
	}
	opts.AddFlags(verifyCmd)
	parentCmd.AddCommand(verifyCmd)
}
