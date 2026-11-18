package main

import "github.com/spf13/cobra"

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "hostscope",
		Short:         "Discover services and system information on a server",
		Long:          "DomainScout is a server discovery CLI that detects configured services and collects system information.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newScanCommand())
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newSystemCommand())
	cmd.AddCommand(newWebCommand())
	cmd.AddCommand(newDomainsCommand())
	cmd.AddCommand(newPortsCommand())
	cmd.AddCommand(newServicesCommand())
	cmd.AddCommand(newSSLCommand())
	cmd.AddCommand(newConfigCommand())

	return cmd
}
