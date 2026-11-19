package rootcli

import (
	"domain-search/cmd/cli"

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
	cmd.AddCommand(cli.NewVersionCommand())
	cmd.AddCommand(cli.NewSystemCommand())
	cmd.AddCommand(cli.NewWebCommand())
	cmd.AddCommand(cli.NewDomainsCommand())
	cmd.AddCommand(cli.NewPortsCommand())
	cmd.AddCommand(cli.NewServicesCommand())
	cmd.AddCommand(cli.NewSSLCommand())
	cmd.AddCommand(cli.NewConfigCommand())

	return cmd
}
