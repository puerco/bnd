// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert/yaml"
)

type predicateOptions struct {
	signOptions
	sigstoreOptions
	outFileOptions
	predicateFileOptions
	SubjectHashes    []string
	SubjectPaths     []string
	SubjectAlgorithm string
}

// Validates the options in context with arguments
func (po *predicateOptions) Validate() error {
	errs := []error{}
	errs = append(errs, po.signOptions.Validate())
	errs = append(errs, po.predicateFileOptions.Validate())
	errs = append(errs, po.sigstoreOptions.Validate())
	errs = append(errs, po.outFileOptions.Validate())

	if len(po.SubjectHashes) == 0 {
		errs = append(errs, errors.New("no subjects specified"))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (po *predicateOptions) AddFlags(cmd *cobra.Command) {
	po.signOptions.AddFlags(cmd)
	po.predicateFileOptions.AddFlags(cmd)
	po.sigstoreOptions.AddFlags(cmd)
	po.outFileOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringSliceVarP(
		&po.SubjectHashes, "subject", "s", []string{}, "list of hashes to add as subjects ",
	)

	cmd.PersistentFlags().StringVar(
		&po.SubjectAlgorithm, "hash-algo", "sha256", "algorithm used to hash the subjects",
	)
}

func addPredicate(parentCmd *cobra.Command) {
	opts := &predicateOptions{}
	attCmd := &cobra.Command{
		Short:             "packs a new attestation into a bundle from a JSON predicate",
		Use:               "predicate",
		Example:           fmt.Sprintf(`%s predicate --type="example.com/v1" --subject-hash=abc123 data.json`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 && opts.PredicatePath == "" {
				return fmt.Errorf("no predicate file specified")
			}

			if len(args) > 0 && opts.PredicatePath != "" {
				opts.PredicatePath = args[0]
			}

			if len(args) > 0 && args[0] != opts.PredicatePath {
				return fmt.Errorf("predicate specified twice (-p and argument)")
			}

			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			var f io.Reader
			f, err := os.Open(opts.PredicatePath)
			if err != nil {
				return fmt.Errorf("opening predicate file: %w", err)
			}

			predData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading predicate data: %s", err)
			}

			if opts.ConvertYAML {
				predData, err = convertYaml(predData)
				if err != nil {
					return err
				}
			}

			optFn := []predicate.ParseOption{}
			if opts.PredicateType != "" {
				optFn = append(optFn, predicate.WithTypeHints(
					[]attestation.PredicateType{
						attestation.PredicateType(opts.PredicateType),
					}),
				)
			}
			pred, err := predicate.Parsers.Parse(predData, optFn...)
			if err != nil {
				return fmt.Errorf("parsing predicate data: %w", err)
			}

			// Create the new attestation
			statement := intoto.NewStatement(intoto.WithPredicate(pred))

			// Add the attestation subjects
			for _, s := range opts.SubjectHashes {
				statement.Subject = append(statement.Subject, &v1.ResourceDescriptor{
					Digest: map[string]string{
						opts.SubjectAlgorithm: s,
					},
				})
			}

			// Marshal the attestation data
			attData, err := statement.ToJson()
			if err != nil {
				return fmt.Errorf("marshaling statement json: %w", err)
			}

			logrus.Debugf("ATTESTATION:\n%s\n/ATTESTATION\n", string(attData))

			signer := getSigner(&opts.sigstoreOptions, &opts.signOptions)

			bundle, err := signer.SignStatement(attData)
			if err != nil {
				return fmt.Errorf("writing signing statement: %w", err)
			}

			o, closer, err := opts.OutputWriter()
			if err != nil {
				return fmt.Errorf("getting output stream: %w", err)
			}
			defer closer()

			if err := signer.WriteBundle(bundle, o); err != nil {
				return err
			}
			return nil
		},
	}
	opts.AddFlags(attCmd)
	parentCmd.AddCommand(attCmd)
}

func convertYaml(in []byte) ([]byte, error) {
	var datamap = &map[string]any{}
	if err := yaml.Unmarshal(in, datamap); err != nil {
		return nil, fmt.Errorf("parsing predicate YAML")
	}

	// Marshal to JSON again
	jsondata, err := json.Marshal(datamap)
	if err != nil {
		return nil, fmt.Errorf("marshalling jsondata: %w", err)
	}
	return jsondata, nil
}
