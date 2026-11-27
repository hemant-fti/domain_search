// Package cli wires hostscope's cobra commands.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"domain-search/models"
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

// DefaultTimeout bounds every command unless --timeout overrides it.
const DefaultTimeout = 2 * time.Minute

// runFunc is the business logic of a command. It receives a context that is
// already bounded by --timeout.
type runFunc func(ctx context.Context, cmd *cobra.Command, args []string) (models.CommandResult, error)

// newResultCommand builds a command with the shared output contract:
// --json, --pretty, --compact, --timeout, --output.
func newResultCommand(use, short string, run runFunc, opts ...func(*cobra.Command)) *cobra.Command {
	o := models.CommandOutputOptions{Timeout: DefaultTimeout, Pretty: true}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Timeout <= 0 {
				return errors.New("timeout must be greater than zero")
			}
			// Args/flags are valid from here on; runtime errors shouldn't dump usage.
			cmd.SilenceUsage = true

			ctx, cancel := context.WithTimeout(commandContext(cmd), o.Timeout)
			defer cancel()

			res, err := run(ctx, cmd, args)
			if err != nil {
				return err
			}

			data, err := render(res, true, o.Pretty && !o.Compact)
			if err != nil {
				return err
			}

			return writeOutput(cmd, o.Output, data)
		},
	}

	f := cmd.Flags()
	f.BoolVar(&o.Jsonl, "json", false, "emit JSON output")
	f.BoolVar(&o.Pretty, "pretty", true, "indent JSON output (implies --json)")
	f.BoolVar(&o.Compact, "compact", false, "emit compact JSON output (implies --json)")
	f.DurationVar(&o.Timeout, "timeout", DefaultTimeout, "maximum command duration")
	f.StringVarP(&o.Output, "output", "o", "", "write the result to a file instead of stdout")

	for _, opt := range opts {
		opt(cmd)
	}
	return cmd
}

func withArgs(v cobra.PositionalArgs) func(*cobra.Command) {
	return func(c *cobra.Command) { c.Args = v }
}

func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func render(res models.CommandResult, asJSON, pretty bool) ([]byte, error) {
	var data []byte
	if asJSON {
		var err error
		if data, err = logger.MarshalJSON(res.Value, pretty); err != nil {
			return nil, fmt.Errorf("encode command result: %w", err)
		}
	} else {
		data = []byte(res.Human)
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return data, nil
}

func writeOutput(cmd *cobra.Command, path string, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	if path == "" {
		_, err := cmd.OutOrStdout().Write(data)
		if err != nil {
			return fmt.Errorf("write command output: %w", err)
		}
		return nil
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write output file %s: %w", path, err)
	}

	return nil
}

func result(value any, human string) models.CommandResult {
	return models.CommandResult{Value: value, Human: human}
}
