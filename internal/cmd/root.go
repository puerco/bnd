// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/carabiner-dev/bind/pkg/bind"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"
)

const appname = "bind"

var rootCmd = &cobra.Command{
	Short: fmt.Sprintf("%s: a utility to work with sigstore bundles", appname),
	Long: fmt.Sprintf(`%s: a utility to work with sigstore bundles
	
bind is a utility that makes it easy to work with attestations and sigstore bundles.
It can create new bundles by "binding" an attestation and signing it. It can verify
existing bundles, extract data from them inspect their contents.

`, appname),
	Use:               appname,
	SilenceUsage:      false,
	PersistentPreRunE: initLogging,
	Example: fmt.Sprintf(`
Create a new bundle by signing and bundling an attestation and its verification
material:

	%s attestation --out=bundle.json att.intoto.json

Inspect the new bundle:
	%s inspect bundle.json
	`, appname, appname),
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

func init() {
	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level",
		"info",
		fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)
	addStatement(rootCmd)
	addPredicate(rootCmd)
	addExtract(rootCmd)
	addInspect(rootCmd)
	addVerify(rootCmd)
	addPush(rootCmd)
	addCommit(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))
}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

// Execute builds the command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

// getSigner builds a bind signer from a sigstore options set
func getSigner(opts *sigstoreOptions) *bind.Signer {
	signer := bind.NewSigner()
	signer.Options.TufRootPath = opts.TufRootPath
	signer.Options.TufRootURL = opts.TufRootURL
	return signer
}
