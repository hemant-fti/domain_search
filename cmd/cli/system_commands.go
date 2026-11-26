package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"domain-search/cmd/output"
	"domain-search/models"
	"domain-search/pkg/logger"
	"domain-search/pkg/system"

	"github.com/spf13/cobra"
)

type uptimeInfo struct {
	Seconds uint64 `json:"seconds"`
	Display string `json:"display"`
}

type systemReport struct {
	System   any      `json:"system"`
	Warnings []string `json:"warnings,omitempty"`
}

func NewSystemCommand() *cobra.Command {
	cmd := newResultCommand("system", "Inspect local system information", runSystemReport)

	cmd.AddCommand(
		inspectCommand("cpu", "Show CPU model and core counts", system.CollectCPUInfo, output.WriteCPU),
		inspectCommand("memory", "Show memory usage", system.CollectMemoryInfo, output.WriteMemory),
		inspectCommand("uptime", "Show system uptime", collectUptime,
			func(w io.Writer, u uptimeInfo) error { return output.WriteUptime(w, u.Seconds) }),
		inspectCommand("disk", "Show disk usage", bind(system.CollectDiskInfo, ""), output.WriteDisk),
	)
	return cmd
}

// inspectCommand builds a leaf command from a collector and a human renderer.
func inspectCommand[T any](
	use, short string,
	collect func(context.Context) (T, error),
	write func(io.Writer, T) error,
) *cobra.Command {
	return newResultCommand(use, short,
		func(ctx context.Context, _ *cobra.Command, _ []string) (models.CommandResult, error) {
			start := time.Now()

			info, err := collect(ctx)
			if err != nil {
				return models.CommandResult{}, fmt.Errorf("%s inspection failed: %w", use, err)
			}

			var human strings.Builder
			if err := write(&human, info); err != nil {
				return models.CommandResult{}, err
			}

			logger.Debug("Inspection completed", "target", use, "duration_ms", time.Since(start).Milliseconds())
			return result(info, human.String()), nil
		})
}

func runSystemReport(ctx context.Context, _ *cobra.Command, _ []string) (models.CommandResult, error) {
	info, warnings, err := system.GetSysInfo(ctx)
	if err != nil {
		return models.CommandResult{}, err
	}

	var human strings.Builder
	if err := output.WriteSystem(&human, info); err != nil {
		return models.CommandResult{}, err
	}
	for _, w := range warnings {
		fmt.Fprintf(&human, "  ⚠ %s\n", w) // strings.Builder writes never fail
	}
	return result(systemReport{System: info, Warnings: warnings}, human.String()), nil
}

func collectUptime(ctx context.Context) (uptimeInfo, error) {
	s, err := system.CollectUptime(ctx)
	if err != nil {
		return uptimeInfo{}, err
	}
	return uptimeInfo{Seconds: s, Display: output.FormatUptime(s)}, nil
}

// bind fixes the second argument of a collector so it fits func(ctx) (T, error).
func bind[T any](f func(context.Context, string) (T, error), arg string) func(context.Context) (T, error) {
	return func(ctx context.Context) (T, error) { return f(ctx, arg) }
}
