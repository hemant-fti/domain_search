package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type commandOutputOptions struct {
	json    bool
	pretty  bool
	compact bool
	timeout time.Duration
	output  string
}

type commandResult struct {
	value any
	human string
}

func newResultCommand(use, short string, run func(context.Context, *cobra.Command) (commandResult, error)) *cobra.Command {
	var options commandOutputOptions
	options.timeout = defaultTimeout
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

			useJSON := options.json || options.compact || cmd.Flags().Changed("pretty")
			if useJSON {
				data, err := marshalJSON(result.value, options.pretty)
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

	cmd.Flags().BoolVar(&options.json, "json", false, "emit JSON output")
	cmd.Flags().BoolVar(&options.pretty, "pretty", true, "indent JSON output (implies --json)")
	cmd.Flags().BoolVar(&options.compact, "compact", false, "emit compact JSON output")
	cmd.Flags().DurationVar(&options.timeout, "timeout", defaultTimeout, "maximum command duration")
	cmd.Flags().StringVarP(&options.output, "output", "o", "", "write the result to a file")
	return cmd
}

func writeCommandOutput(cmd *cobra.Command, path string, data []byte) error {
	if path != "" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write output file %s: %w", path, err)
		}

		captureCommandFileOutput(cmd.Context(), data)
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

func newSystemCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "system", Short: "Inspect local system information"}
	cmd.AddCommand(newSystemInfoCommand())
	cmd.AddCommand(newSystemCPUCommand())
	cmd.AddCommand(newSystemMemoryCommand())
	cmd.AddCommand(newSystemDiskCommand())
	cmd.AddCommand(newSystemNetworkCommand())
	cmd.AddCommand(newSystemUptimeCommand())
	return cmd
}

func newWebCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "web", Short: "Inspect configured web servers"}
	cmd.AddCommand(newWebListCommand())
	cmd.AddCommand(newWebServerCommand("nginx"))
	cmd.AddCommand(newWebServerCommand("apache"))
	cmd.AddCommand(newWebStatusCommand())
	return cmd
}

func newDomainsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "domains", Short: "Discover configured domains and perform DNS lookups"}
	cmd.AddCommand(newDomainsListCommand())
	cmd.AddCommand(newDomainsServerCommand("nginx"))
	cmd.AddCommand(newDomainsServerCommand("apache"))
	cmd.AddCommand(newDomainsDNSCommand())
	cmd.AddCommand(newDomainsGetdatabyServerNameCommand())
	return cmd
}

func newPortsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "ports", Short: "List local TCP and UDP sockets"}
	cmd.AddCommand(newPortsListCommand(""))
	cmd.AddCommand(newPortsListCommand("tcp"))
	cmd.AddCommand(newPortsListCommand("udp"))
	return cmd
}

func newServicesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "services", Short: "Inspect system services"}
	cmd.AddCommand(newServicesListCommand())
	cmd.AddCommand(newServiceStatusCommand())
	return cmd
}

func newSSLCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "ssl", Short: "Inspect certificates referenced by local web server configuration"}
	cmd.AddCommand(newCertificateCommand("list"))
	cmd.AddCommand(newCertificateCommand("check"))
	return cmd
}

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect web server configuration"}
	cmd.AddCommand(newConfigServerCommand("nginx"))
	cmd.AddCommand(newConfigServerCommand("apache"))
	return cmd
}
