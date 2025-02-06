// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/carabiner-dev/bind/internal/git"
	"github.com/carabiner-dev/bind/pkg/bundle"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// commitOptions
type commitOptions struct {
	predicateFileOptions
	signOptions
	outFileOptions
	RepoURL          string
	RepoPath         string
	Sha              string
	Tag              string
	PredicateGitPath string
}

// Validate checks the options
func (co *commitOptions) Validate() error {
	errs := []error{}
	errs = append(errs, co.signOptions.Validate())
	errs = append(errs, co.predicateFileOptions.Validate())
	errs = append(errs, co.outFileOptions.Validate())

	if co.Sha != "" && co.Tag != "" {
		errs = append(errs, errors.New("only tag or commit hash can be specified at the same time"))
	}

	if co.PredicatePath == "" && co.PredicateGitPath == "" {
		errs = append(errs, errors.New("no predicate file specified"))
	}

	if co.PredicatePath != "" && co.PredicateGitPath != "" {
		errs = append(errs, errors.New("predicater specified as file and as checked data"))
	}

	if co.Tag != "" && (co.RepoURL == "" && co.RepoPath == "") {
		errs = append(errs, errors.New("repo URL or repo path must be sepcified whe attesting a git tag"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (co *commitOptions) AddFlags(cmd *cobra.Command) {
	co.signOptions.AddFlags(cmd)
	co.predicateFileOptions.AddFlags(cmd)
	co.outFileOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(
		&co.Sha, "sha", "", "commit hash to attest (defaults to HEAD of main branch)",
	)

	cmd.PersistentFlags().StringVar(
		&co.Tag, "tag", "", "use a tag instead of a commit hash",
	)

	cmd.PersistentFlags().StringVarP(
		&co.RepoURL, "repo", "r", "", "url of the repository to clone",
	)

	cmd.PersistentFlags().StringVar(
		&co.PredicateGitPath, "git-predicate", "", "path to the predicate in the local repo",
	)
}

func addCommit(parentCmd *cobra.Command) {
	opts := commitOptions{}
	commitCmd := &cobra.Command{
		Short: "attests to data of a commit",
		Long: fmt.Sprintf(`
🥨 %s commit

The commit subcommand generates statments about git commits. This lets
tools create attestations about the status of a repo at a point in time.

This is not intended to replace commit signing tools such as gittuf or
gitsign but rather to make it easy to associate predicates with a repository's
history.

The predicate data can be read from commited files or can be supplied externally.
The commit subcommmand can clone local or remote repositories. It can also
resolve tags, generating the correct subjects with their current hash.

Note that %s commit always clones the repo, even when operating on local 
repositories from disk. The purpose is to avoid messing up you environment as
the commit subcommand moves HEAD around.

	`, appname, appname),
		Use:               "commit",
		Example:           fmt.Sprintf(`%s commit --type="example.com/v1" --tag=v1.0.0 --from`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.PredicatePath != "" {
				opts.PredicatePath = args[0]
			}

			if len(args) > 0 && args[0] != opts.PredicatePath {
				return fmt.Errorf("predicate specified twice (-p and argument)")
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			ctx := context.Background()

			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			if opts.RepoURL != "" {
				logrus.Debugf("cloning %s", opts.RepoURL)
				path, _, err := git.CloneOrOpenCommit(opts.RepoURL, opts.Sha)
				if err != nil {
					return fmt.Errorf("cloning remote repo: %w", err)
				}
				if path == "" {
					return errors.New("no repo path received from cloning operation")
				}
				opts.RepoPath = path
			} else {
				return fmt.Errorf("local repo not implemented yet")
			}

			// Use the predicate path from the options
			predicatePath := opts.PredicatePath
			//  ... unless its pointing to the cloned repo
			if opts.PredicateGitPath != "" {
				if opts.RepoPath == "" {
					return errors.New("repo path not set")
				}
				predicatePath = path.Join(opts.RepoPath, opts.PredicateGitPath)
			}

			var f io.Reader
			f, err := os.Open(predicatePath)
			if err != nil {
				return fmt.Errorf("opening predicate file: %w", err)
			}

			predData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading predicate data: %s", err)
			}

			// Convert if we're reading YAML
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

			// Marshal the attestation data
			attData, err := statement.ToJson()
			if err != nil {
				return fmt.Errorf("marshaling statement json: %w", err)
			}

			logrus.Debugf("ATTESTATION:\n%s\n/ATTESTATION\n", string(attData))

			signer := bundle.NewSigner()
			bundle, err := signer.SignAndBind(ctx, attData)
			if err != nil {
				return fmt.Errorf("binding statement: %w", err)
			}

			data, err := protojson.Marshal(bundle)
			if err != nil {
				return fmt.Errorf("marshaling bundle: %w", err)
			}

			o, closer, err := opts.OutputWriter()
			if err != nil {
				return err
			}
			defer closer()

			if _, err := o.Write(data); err != nil {
				return fmt.Errorf("writing bundle data: %w", err)
			}

			return nil
		},
	}
	opts.AddFlags(commitCmd)
	parentCmd.AddCommand(commitCmd)
}
