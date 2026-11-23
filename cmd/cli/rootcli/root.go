package rootcli

import (
	"domain-search/cmd/cli"
	"fmt"

	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "hostscope",
		Short:         "Discover services and system information on a server",
		Long:          "DomainScout is a server discovery CLI that detects configured services and collects system information.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(cli.NewScanCommand())
	cmd.AddCommand(NewVersionCommand())
	cmd.AddCommand(cli.NewSystemCommand())
	cmd.AddCommand(cli.NewDomainsCommand())

	return cmd
}

const version = "1.1.0"

func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display DomainScout version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "hostscope %s\n", version)
		},
	}
}
