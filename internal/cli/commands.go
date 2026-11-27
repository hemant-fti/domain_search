// Package cli defines hostscope's cobra commands and interactive menu.
//
// Commands are presentation only: they call internal/scan and pkg/ packages,
// render the result with internal/cli/render and record it in the
// application log.
package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

// DefaultTimeout bounds every command unless --timeout overrides it.
const DefaultTimeout = 2 * time.Minute

// commandResult is what a command produces: a structured value for the
// application log and the human-readable text for the terminal.
type commandResult struct {
	Value any
	Human string
}

// runFunc is the business call of a command. It receives a context that is
// already bounded by --timeout.
type runFunc func(ctx context.Context, cmd *cobra.Command, args []string) (commandResult, error)

// newResultCommand builds a command with the shared contract: a --timeout
// flag, human output on stdout and the structured result appended to the
// application log (application.jsonl).
func newResultCommand(use, short string, run runFunc, opts ...func(*cobra.Command)) *cobra.Command {
	timeout := DefaultTimeout

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if timeout <= 0 {
				return errors.New("timeout must be greater than zero")
			}
			cmd.SilenceUsage = true

			ctx, cancel := context.WithTimeout(commandContext(cmd), timeout)
			defer cancel()

			res, err := run(ctx, cmd, args)
			if err != nil {
				return err
			}

			if _, err := fmt.Fprint(cmd.OutOrStdout(), res.Human); err != nil {
				return fmt.Errorf("write terminal output: %w", err)
			}
			logger.Info("Command output", "command", cmd.CommandPath(), "result", res.Value)
			return nil
		},
	}

	cmd.Flags().DurationVar(&timeout, "timeout", DefaultTimeout, "maximum command duration")

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

func result(value any, human string) commandResult {
	return commandResult{Value: value, Human: human}
}
