// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

type pushOptions struct {
	bundleOptions
}

// Validate the options in context with arguments
func (o *pushOptions) Validate() error {
	return errors.Join(
		o.bundleOptions.Validate(),
	)
}

func (o *pushOptions) AddFlags(cmd *cobra.Command) {
	o.bundleOptions.AddFlags(cmd)
}

func addPush(parentCmd *cobra.Command) {
	opts := pushOptions{}
	pushCmd := &cobra.Command{
		Short:             "pushes an attestation or bundle to github or an OCI registry",
		Use:               "push",
		SilenceUsage:      false,
		SilenceErrors:     true,
		Hidden:            true,
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

			return nil
		},
	}

	parentCmd.AddCommand(pushCmd)
}
