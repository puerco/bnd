// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/bnd/pkg/upload"
	"github.com/spf13/cobra"
)

type pushOptions struct {
	Bundles  []string
	RepoName string
	RepoOrg  string
}

// Validate the options in context with arguments
func (o *pushOptions) Validate() error {
	errs := []error{}

	if len(o.Bundles) == 0 {
		errs = append(errs, errors.New("no bundles specified"))
	}

	if o.RepoName == "" {
		errs = append(errs, errors.New("repository name not set"))
	}

	if o.RepoOrg == "" {
		errs = append(errs, errors.New("repository organization not set"))
	}

	return errors.Join(errs...)
}

func (o *pushOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&o.Bundles,
		"bundle", "b", []string{}, "path to bundle",
	)

	cmd.PersistentFlags().StringVarP(
		&o.RepoName,
		"repo", "r", "", "repository name",
	)

	cmd.PersistentFlags().StringVar(
		&o.RepoOrg,
		"org", "", "repository organization",
	)
}

func addPush(parentCmd *cobra.Command) {
	opts := pushOptions{}
	pushCmd := &cobra.Command{
		Short: "pushes an attestation or bundle to github or an OCI registry",
		Long: fmt.Sprintf(`
🥨 %s push: Push attestations and bundles to remote

The push subcommand lets you send bundled attestations to remote storage
locations. Initial support is provided for the GitHub attestation store
but more drivers are on the way.

`, appname),
		Use:           "push [flags] [org/repo [bundle.json...]]",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: fmt.Sprintf(`
Push an attestation bundle to GitHub:

%s push --bundle bundle.json --repo myorg --org repo

Same but with shortcut positional arguments:

%s push myorg/repo bundle.json

`, appname, appname),
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 && opts.RepoName != "" && opts.RepoOrg != "" {
				if args[0] != fmt.Sprintf("%s/%s", opts.RepoOrg, opts.RepoName) {
					return fmt.Errorf("repo data specified twice (arg and flags)")
				}
			}

			if len(args) > 0 {
				org, name, did := strings.Cut(args[0], "/")
				if did {
					opts.RepoName = name
					opts.RepoOrg = org
				}
			}

			if len(args) > 1 {
				opts.Bundles = append(opts.Bundles, args[1:]...)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			client := upload.NewClient()

			for _, bundlePath := range opts.Bundles {
				if err := client.PushBundleFileToGithub(opts.RepoOrg, opts.RepoName, bundlePath); err != nil {
					return fmt.Errorf("pushing %q: %w", bundlePath, err)
				}
			}
			return nil
		},
	}
	opts.AddFlags(pushCmd)
	parentCmd.AddCommand(pushCmd)
}
