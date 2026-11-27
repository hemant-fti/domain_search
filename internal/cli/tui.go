package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"domain-search/pkg/tui"

	"github.com/spf13/cobra"
)

// NewTUICommand returns the `tui` command.
func NewTUICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive menu",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runTUI(cmd.Context()) },
	}
}

func runTUI(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stdin := bufio.NewReader(os.Stdin)

	for {
		var (
			next   []string // command to run after the menu closes
			picked bool     // false means the user chose Quit
		)
		pick := func(args ...string) tui.Action {
			return func() error { next, picked = args, true; return nil }
		}

		app := tui.New(tui.Config{
			Title:       "Hostscope",
			Subtitle:    "Server discovery & system inspection",
			Version:     version,
			ShowNumbers: true,
		})

		app.AddSeparator("Discovery")
		app.AddItem(tui.MenuItem{Title: "Full scan", Description: "Detect services and system info", Exit: true, Action: pick("scan")})
		app.AddItem(tui.MenuItem{Title: "List domains", Description: "Virtual hosts from all web servers", Exit: true, Action: pick("domains", "list")})
		app.AddItem(tui.MenuItem{Title: "Find domain…", Description: "Look up one domain by name", Exit: true, Action: func() error {
			fmt.Print("Domain name: ")
			line, _ := stdin.ReadString('\n')
			picked = true
			if name := strings.TrimSpace(line); name != "" {
				next = []string{"domains", "get-data-by-name", name}
			}
			return nil
		}})

		app.AddSeparator("System")
		app.AddItem(tui.MenuItem{Title: "System report", Exit: true, Action: pick("system")})
		app.AddItem(tui.MenuItem{Title: "CPU", Exit: true, Action: pick("system", "cpu")})
		app.AddItem(tui.MenuItem{Title: "Memory", Exit: true, Action: pick("system", "memory")})
		app.AddItem(tui.MenuItem{Title: "Disk", Exit: true, Action: pick("system", "disk")})
		app.AddItem(tui.MenuItem{Title: "Uptime", Exit: true, Action: pick("system", "uptime")})

		app.AddSeparator("")
		app.AddExitMenu("Quit")

		if err := app.Run(); err != nil {
			return err
		}
		if !picked {
			return nil // Quit, Esc, or Ctrl+C
		}
		if len(next) > 0 {
			if err := runSubcommand(ctx, next); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
			fmt.Print("\nPress Enter to return to the menu…")
			_, _ = stdin.ReadString('\n')
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// runSubcommand executes a fresh root command so flags never leak between runs.
func runSubcommand(ctx context.Context, args []string) error {
	root := NewRootCommand()
	root.SetArgs(args)
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	return root.ExecuteContext(ctx)
}
