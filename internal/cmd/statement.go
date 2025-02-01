// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/bind/pkg/bundle"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

type statementOptions struct {
	signOptions
}

// Validates the options in context with arguments
func (so *statementOptions) Validate() error {
	errs := []error{}
	errs = append(errs, so.signOptions.Validate())
	return errors.Join(errs...)
}

func (so *statementOptions) AddFlags(cmd *cobra.Command) {
	so.signOptions.AddFlags(cmd)
}

func addStatement(parentCmd *cobra.Command) {
	opts := statementOptions{}
	attCmd := &cobra.Command{
		Short:             fmt.Sprintf("%s statement: binds an in-toto attestation in a signed bundle", appname),
		Use:               "statement",
		Example:           fmt.Sprintf("%s statement file.intoto.json ", appname),
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
				return fmt.Errorf("opening statement file")
			}

			attData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading statement data: %s", err)
			}

			signer := bundle.NewSigner()
			bundle, err := signer.SignAndBind(ctx, attData)
			if err != nil {
				return fmt.Errorf("binding statement: %w", err)
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
