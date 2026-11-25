package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"domain-search/cmd/history"
	"domain-search/models"

	"github.com/spf13/cobra"
)

const DefaultTimeout = 2 * time.Minute

func newResultCommand(use, short string, run func(context.Context, *cobra.Command) (models.CommandResult, error)) *cobra.Command {
	var options models.CommandOutputOptions
	options.Timeout = DefaultTimeout
	options.Pretty = true

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if options.Timeout <= 0 {
				return fmt.Errorf("Timeout must be greater than zero")
			}
			if options.Compact {
				options.Pretty = false
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
			defer cancel()

			result, err := run(ctx, cmd)
			if err != nil {
				return err
			}

			useJSON := options.Jsonl || options.Compact || cmd.Flags().Changed("Pretty")
			if useJSON {
				data, err := history.MarshalJSON(result.Value, options.Pretty)
				if err != nil {
					return fmt.Errorf("encode command result: %w", err)
				}
				if err := writeCommandOutput(cmd, options.Output, data); err != nil {
					return fmt.Errorf("write command result: %w", err)
				}
				return nil
			}

			if result.Human == "" {
				return nil
			}
			if result.Human[len(result.Human)-1] != '\n' {
				result.Human += "\n"
			}
			if err := writeCommandOutput(cmd, options.Output, []byte(result.Human)); err != nil {
				return fmt.Errorf("write command result: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&options.Jsonl, "json", false, "emit JSON Output")
	cmd.Flags().BoolVar(&options.Pretty, "Pretty", true, "indent JSON Output (implies --json)")
	cmd.Flags().BoolVar(&options.Compact, "Compact", false, "emit Compact JSON Output")
	cmd.Flags().DurationVar(&options.Timeout, "Timeout", DefaultTimeout, "maximum command duration")
	cmd.Flags().StringVarP(&options.Output, "Output", "o", "", "write the result to a file")
	return cmd
}

func writeCommandOutput(cmd *cobra.Command, path string, data []byte) error {
	if path != "" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write Output file %s: %w", path, err)
		}

		history.CaptureCommandFileOutput(cmd.Context(), data)
		return nil
	}

	if _, err := cmd.OutOrStdout().Write(data); err != nil {
		return err
	}

	return nil
}

func textResult(Value any, Human string) models.CommandResult {
	return models.CommandResult{Value: Value, Human: Human}
}

func NewSystemCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "system", Short: "Inspect local system information"}
	cmd.AddCommand(NewSystemCPUCommand())
	cmd.AddCommand(NewSystemMemoryCommand())
	cmd.AddCommand(NewSystemUptimeCommand())
	cmd.AddCommand(NewDiskUsageCommand())
	return cmd
}

func NewDomainsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "domains", Short: "Discover configured domains and perform DNS lookups"}
	cmd.AddCommand(NewDomainsListCommand())
	cmd.AddCommand(NewDomainsGetdatabyServerNameCommand())
	return cmd
}
