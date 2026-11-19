package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

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
