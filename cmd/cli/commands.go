package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"domain-search/cmd/history"
	cmdoutput "domain-search/cmd/output"

	"github.com/spf13/cobra"
)

type commandOutputOptions struct {
	jsonl   bool
	pretty  bool
	compact bool
	timeout time.Duration
	output  string
}

type commandResult struct {
	value any
	human string
}

const DefaultTimeout = 2 * time.Minute

func newResultCommand(use, short string, run func(context.Context, *cobra.Command) (commandResult, error)) *cobra.Command {
	var options commandOutputOptions
	options.timeout = DefaultTimeout
	options.pretty = true

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if options.timeout <= 0 {
				return fmt.Errorf("timeout must be greater than zero")
			}
			if options.compact {
				options.pretty = false
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
			defer cancel()

			result, err := run(ctx, cmd)
			if err != nil {
				return err
			}

			useJSON := options.jsonl || options.compact || cmd.Flags().Changed("pretty")
			if useJSON {
				data, err := cmdoutput.MarshalJSON(result.value, options.pretty)
				if err != nil {
					return fmt.Errorf("encode command result: %w", err)
				}
				if err := writeCommandOutput(cmd, options.output, data); err != nil {
					return fmt.Errorf("write command result: %w", err)
				}
				return nil
			}

			if result.human == "" {
				return nil
			}
			if result.human[len(result.human)-1] != '\n' {
				result.human += "\n"
			}
			if err := writeCommandOutput(cmd, options.output, []byte(result.human)); err != nil {
				return fmt.Errorf("write command result: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&options.jsonl, "json", false, "emit JSON output")
	cmd.Flags().BoolVar(&options.pretty, "pretty", true, "indent JSON output (implies --json)")
	cmd.Flags().BoolVar(&options.compact, "compact", false, "emit compact JSON output")
	cmd.Flags().DurationVar(&options.timeout, "timeout", DefaultTimeout, "maximum command duration")
	cmd.Flags().StringVarP(&options.output, "output", "o", "", "write the result to a file")
	return cmd
}

func writeCommandOutput(cmd *cobra.Command, path string, data []byte) error {
	if path != "" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write output file %s: %w", path, err)
		}

		history.CaptureCommandFileOutput(cmd.Context(), data)
		return nil
	}

	if _, err := cmd.OutOrStdout().Write(data); err != nil {
		return err
	}

	return nil
}

func textResult(value any, human string) commandResult {
	return commandResult{value: value, human: human}
}

func NewSystemCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "system", Short: "Inspect local system information"}
	cmd.AddCommand(NewSystemInfoCommand())
	cmd.AddCommand(NewSystemCPUCommand())
	cmd.AddCommand(NewSystemMemoryCommand())
	cmd.AddCommand(NewSystemDiskCommand())
	cmd.AddCommand(NewSystemNetworkCommand())
	cmd.AddCommand(NewSystemUptimeCommand())
	return cmd
}

func NewWebCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "web", Short: "Inspect configured web servers"}
	cmd.AddCommand(NewWebListCommand())
	cmd.AddCommand(NewWebServerCommand("nginx"))
	cmd.AddCommand(NewWebServerCommand("apache"))
	cmd.AddCommand(NewWebStatusCommand())
	return cmd
}

func NewDomainsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "domains", Short: "Discover configured domains and perform DNS lookups"}
	cmd.AddCommand(NewDomainsListCommand())
	cmd.AddCommand(NewDomainsServerCommand("nginx"))
	cmd.AddCommand(NewDomainsServerCommand("apache"))
	cmd.AddCommand(NewDomainsDNSCommand())
	cmd.AddCommand(NewDomainsGetdatabyServerNameCommand())
	return cmd
}

func NewPortsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "ports", Short: "List local TCP and UDP sockets"}
	cmd.AddCommand(NewPortsListCommand(""))
	cmd.AddCommand(NewPortsListCommand("tcp"))
	cmd.AddCommand(NewPortsListCommand("udp"))
	return cmd
}

func NewServicesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "services", Short: "Inspect system services"}
	cmd.AddCommand(NewServicesListCommand())
	cmd.AddCommand(NewServiceStatusCommand())
	return cmd
}

func NewSSLCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "ssl", Short: "Inspect certificates referenced by local web server configuration"}
	cmd.AddCommand(NewCertificateCommand("list"))
	cmd.AddCommand(NewCertificateCommand("check"))
	return cmd
}

func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect web server configuration"}
	cmd.AddCommand(NewConfigServerCommand("nginx"))
	cmd.AddCommand(NewConfigServerCommand("apache"))
	return cmd
}
