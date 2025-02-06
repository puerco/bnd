// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

type predicateFileOptions struct {
	PredicateType string
	PredicatePath string
	ConvertYAML   bool
}

func (pfo *predicateFileOptions) Validate() error {
	return nil
}

func (pfo *predicateFileOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&pfo.PredicateType, "type", "t", "",
		"predicate type to declare in the attestation (defaults to autodetect)",
	)

	cmd.PersistentFlags().StringVarP(
		&pfo.PredicatePath, "predicate", "p", "",
		"path to the json predicate data file",
	)

	cmd.PersistentFlags().BoolVar(
		&pfo.ConvertYAML,
		"yaml",
		false,
		"convert a yaml file to JSON before attesting it",
	)
}
