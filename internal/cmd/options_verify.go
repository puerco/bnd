package cmd

import "github.com/spf13/cobra"

type verifcationOptions struct {
	RequireCTlog     bool
	RequireTimestamp bool
	RequireTlog      bool
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
}

func (vo *verifcationOptions) Validate() error {
	return nil
}
