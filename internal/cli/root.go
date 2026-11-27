package cli

import (
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

// NewRootCommand returns the hostscope root command. Without a subcommand
// it opens the interactive menu.
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "hostscope",
		Short:         "Discover services and system information on a server",
		Long:          "Hostscope is a server discovery CLI that detects configured services and collects system information.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd.Context())
		},
	}

	cmd.AddCommand(NewScanCommand())
	cmd.AddCommand(NewVersionCommand())
	cmd.AddCommand(NewSystemCommand())
	cmd.AddCommand(NewDomainsCommand())
	cmd.AddCommand(NewTUICommand())

	return cmd
}

const version = "1.0.0"

// NewVersionCommand returns the `version` command.
func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display Hostscope version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := logger.MarshalJSON(map[string]string{
				"version": version,
			}, true)
			if err != nil {
				return err
			}

			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}
