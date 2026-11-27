// Package cli wires hostscope's cobra commands.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

			cmd.SilenceUsage = true

			ctx, cancel := context.WithTimeout(commandContext(cmd), o.Timeout)
			defer cancel()

			res, err := run(ctx, cmd, args)
			if err != nil {
				return err
			}

			// Print human-readable output only in the terminal.
			if _, err := fmt.Fprint(cmd.OutOrStdout(), res.Human); err != nil {
				return fmt.Errorf("write terminal output: %w", err)
			}

			// Automatically save structured JSON.
			data, err := logger.MarshalJSON(res.Value, true)
			if err != nil {
				return fmt.Errorf("encode command result: %w", err)
			}

			outputDir := "output"
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}

			filename := strings.ReplaceAll(cmd.CommandPath(), " ", "-") + ".json"
			outputPath := filepath.Join(outputDir, filename)

			if err := os.WriteFile(outputPath, data, 0600); err != nil {
				return fmt.Errorf("save JSON output: %w", err)
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&o.Jsonl, "json", false, "emit JSON output")
	f.BoolVar(&o.Pretty, "pretty", true, "indent JSON output (implies --json)")
	f.BoolVar(&o.Compact, "compact", false, "emit compact JSON output (implies --json)")
	f.DurationVar(&o.Timeout, "timeout", DefaultTimeout, "maximum command duration")
	f.StringVarP(&o.Output, "output", "o", "", "write structured JSON output to a file while keeping human output in the terminal")

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

func result(value any, human string) models.CommandResult {
	return models.CommandResult{Value: value, Human: human}
}
