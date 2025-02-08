package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

type verifcationOptions struct {
	RequireCTlog        bool
	RequireTimestamp    bool
	RequireTlog         bool
	SkipIdentityCheck   bool
	ExpectedIssuer      string
	ExpectedIssuerRegex string
	ExpectedSan         string
	ExpectedSanRegex    string
}

func (vo *verifcationOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&vo.RequireCTlog, "ctlog", true,
		"require and check RFC 3161 timestamps in the verified bundle",
	)

	cmd.PersistentFlags().BoolVar(
		&vo.RequireTlog, "tlog", true,
		"look for transparency log inclusion proof when verifying",
	)

	cmd.PersistentFlags().BoolVar(
		&vo.RequireTimestamp, "timestamps", true,
		"look for observer timestamps when verifying",
	)

	cmd.PersistentFlags().BoolVar(
		&vo.SkipIdentityCheck, "skip-identity", false,
		"allow skipping identity verification",
	)

	cmd.PersistentFlags().StringVar(
		&vo.ExpectedSan, "identity", "",
		"expected certificate identity (SAN)",
	)

	cmd.PersistentFlags().StringVar(
		&vo.ExpectedSanRegex, "identity-regex", "",
		"regex to check the certificate identity (SAN)",
	)

	cmd.PersistentFlags().StringVar(
		&vo.ExpectedIssuer, "issuer", "",
		"expected OIDC issuer for the certificate identity",
	)

	cmd.PersistentFlags().StringVar(
		&vo.ExpectedIssuerRegex, "issuer-regex", "",
		"regex to check the certificate's OIDC identity issuer",
	)
}

func (vo *verifcationOptions) Validate() error {
	errs := []error{}
	if vo.ExpectedIssuer != "" && vo.ExpectedIssuerRegex != "" {
		errs = append(errs, errors.New("only one of issuer or issuer-regexp can be set at the same"))
	}
	if vo.ExpectedSan != "" && vo.ExpectedSanRegex != "" {
		errs = append(errs, errors.New("only one of identity or identity-regexp can be set at the same"))
	}
	return errors.Join(errs...)
}
