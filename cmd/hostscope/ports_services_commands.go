package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	ssh "domain-search/internal/os"
	"domain-search/internal/ports"
)

func newPortsListCommand(fixedProtocol string) *cobra.Command {
	use := "list"
	short := "List local listening TCP and UDP sockets"
	if fixedProtocol != "" {
		use = fixedProtocol
		short = "List local " + strings.ToUpper(fixedProtocol) + " sockets"
	}

	var protocol, state, portRange string
	var port int
	var pid int
	var includeProcess, all bool
	cmd := newResultCommand(use, short, func(ctx context.Context, cmd *cobra.Command) (commandResult, error) {
		selectedProtocol := protocol
		if fixedProtocol != "" {
			selectedProtocol = fixedProtocol
		}
		if all && !cmd.Flags().Changed("state") {
			state = ""
		}
		options := ports.Options{
			Protocol:       selectedProtocol,
			State:          state,
			Port:           uint32(port),
			PID:            int32(pid),
			IncludeProcess: includeProcess,
			All:            all,
		}
		if portRange != "" {
			parts := strings.Split(portRange, "-")
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			options.RangeStart, options.RangeEnd = uint32(start), uint32(end)
		}
		listeners, err := ports.List(ctx, options)
		if err != nil {
			return commandResult{}, err
		}
		if len(listeners) == 0 {
			return textResult(listeners, "No matching local sockets were found."), nil
		}
		lines := make([]string, 0, len(listeners))
		for _, listener := range listeners {
			line := fmt.Sprintf("%s %s:%d %s", strings.ToUpper(listener.Protocol), listener.Address, listener.Port, listener.State)
			if listener.PID > 0 {
				line += fmt.Sprintf(" pid=%d", listener.PID)
			}
			if listener.Process != "" {
				line += " process=" + listener.Process
			}
			lines = append(lines, line)
		}
		return textResult(listeners, strings.Join(lines, "\n")), nil
	})
	cmd.Flags().StringVar(&protocol, "protocol", "", "filter by tcp or udp")
	cmd.Flags().StringVar(&state, "state", "listening", "socket state (TCP listening; UDP bound)")
	cmd.Flags().IntVar(&port, "port", 0, "filter by local port")
	cmd.Flags().BoolVar(&includeProcess, "process", false, "include process names")
	cmd.Flags().IntVar(&pid, "pid", 0, "filter by process ID")
	cmd.Flags().StringVar(&portRange, "range", "", "filter by local port range, for example 8000-9000")
	cmd.Flags().BoolVar(&all, "all", false, "include non-listening TCP connections")
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		if protocol != "" && protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("--protocol must be tcp or udp")
		}
		if (cmd.Flags().Changed("port") && port < 1) || port > 65535 {
			return fmt.Errorf("--port must be between 1 and 65535")
		}
		if pid < 0 {
			return fmt.Errorf("--pid cannot be negative")
		}
		if portRange != "" {
			parts := strings.Split(portRange, "-")
			if len(parts) != 2 {
				return fmt.Errorf("--range must use the form START-END")
			}
			start, startErr := strconv.Atoi(parts[0])
			end, endErr := strconv.Atoi(parts[1])
			if startErr != nil || endErr != nil || start < 1 || end > 65535 || start > end {
				return fmt.Errorf("--range must contain ports from 1 through 65535 in ascending order")
			}
			if port != 0 {
				return fmt.Errorf("--port and --range cannot be used together")
			}
		}
		if fixedProtocol != "" && protocol != "" && protocol != fixedProtocol {
			return fmt.Errorf("the %s command cannot be used with --protocol %s", fixedProtocol, protocol)
		}
		return nil
	}
	return cmd
}

type serviceRecord struct {
	Name    string `json:"name"`
	Active  string `json:"active"`
	Sub     string `json:"sub_state,omitempty"`
	Enabled string `json:"enabled"`
}

var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:-]*$`)

func listServices(ctx context.Context, ex ssh.Executor) ([]serviceRecord, error) {
	if err := ensureLinux("system service inspection"); err != nil {
		return nil, err
	}
	if _, err := ex.Run(ctx, "systemctl --version"); err != nil {
		return nil, fmt.Errorf("systemd is unavailable: %w", err)
	}
	units, err := ex.Run(ctx, "systemctl list-unit-files --type=service --no-pager --no-legend")
	if err != nil {
		return nil, fmt.Errorf("list system service files: %w", err)
	}
	activeUnits, err := ex.Run(ctx, "systemctl list-units --type=service --all --no-pager --plain --no-legend")
	if err != nil {
		return nil, fmt.Errorf("list system services: %w", err)
	}

	results := make(map[string]*serviceRecord)
	for _, line := range strings.Split(units, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		results[fields[0]] = &serviceRecord{Name: fields[0], Enabled: fields[1], Active: "inactive"}
	}
	for _, line := range strings.Split(activeUnits, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		record, ok := results[fields[0]]
		if !ok {
			record = &serviceRecord{Name: fields[0], Enabled: "unknown"}
			results[fields[0]] = record
		}
		record.Active = fields[2]
		record.Sub = fields[3]
	}

	list := make([]serviceRecord, 0, len(results))
	for _, record := range results {
		list = append(list, *record)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func newServicesListCommand() *cobra.Command {
	var running, stopped, enabled bool
	cmd := newResultCommand("list", "List system services and their status", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		services, err := listServices(ctx, ssh.NewLocalExecutor())
		if err != nil {
			return commandResult{}, err
		}
		filtered := make([]serviceRecord, 0, len(services))
		for _, service := range services {
			isRunning := service.Active == "active"
			if running && !isRunning || stopped && isRunning {
				continue
			}
			if enabled && service.Enabled != "enabled" && service.Enabled != "enabled-runtime" {
				continue
			}
			filtered = append(filtered, service)
		}
		lines := make([]string, 0, len(filtered))
		for _, service := range filtered {
			lines = append(lines, fmt.Sprintf("%s\t%s (%s)", service.Name, service.Active, service.Enabled))
		}
		if len(lines) == 0 {
			return textResult(filtered, "No matching services were found."), nil
		}
		return textResult(filtered, strings.Join(lines, "\n")), nil
	})
	cmd.Flags().BoolVar(&running, "running", false, "show only running services")
	cmd.Flags().BoolVar(&stopped, "stopped", false, "show only stopped services")
	cmd.Flags().BoolVar(&enabled, "enabled", false, "show only enabled services")
	cmd.PreRunE = func(_ *cobra.Command, _ []string) error {
		if running && stopped {
			return fmt.Errorf("--running and --stopped cannot be used together")
		}
		return nil
	}
	return cmd
}

func newServiceStatusCommand() *cobra.Command {
	var serviceName string
	cmd := newResultCommand("status <service>", "Show active and enabled state for a service", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		if err := ensureLinux("system service inspection"); err != nil {
			return commandResult{}, err
		}
		name := serviceName
		if !serviceNamePattern.MatchString(name) {
			return commandResult{}, fmt.Errorf("invalid service name %q", name)
		}
		if !strings.HasSuffix(name, ".service") {
			name += ".service"
		}
		ex := ssh.NewLocalExecutor()
		if _, err := ex.Run(ctx, "systemctl --version"); err != nil {
			return commandResult{}, fmt.Errorf("systemd is unavailable: %w", err)
		}
		active, err := serviceState(ctx, ex, "is-active", name)
		if err != nil {
			return commandResult{}, err
		}
		enabled, err := serviceState(ctx, ex, "is-enabled", name)
		if err != nil {
			return commandResult{}, err
		}
		if ctx.Err() != nil {
			return commandResult{}, ctx.Err()
		}
		result := serviceRecord{Name: name, Active: active, Enabled: enabled}
		return textResult(result, fmt.Sprintf("%s: %s (%s)", name, active, enabled)), nil
	})
	cmd.Args = cobra.ExactArgs(1)
	cmd.PreRunE = func(_ *cobra.Command, args []string) error {
		serviceName = args[0]
		return nil
	}
	return cmd
}

func serviceState(ctx context.Context, ex ssh.Executor, operation, service string) (string, error) {
	output, err := ex.Run(ctx, "systemctl "+operation+" "+service)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	value := strings.TrimSpace(output)
	if value == "" {
		if err != nil {
			return "", fmt.Errorf("read %s service state: %w", operation, err)
		}
		return "", fmt.Errorf("read %s service state: systemctl returned no status", operation)
	}
	if err != nil {
		known := map[string]bool{
			"active": true, "inactive": true, "failed": true, "activating": true,
			"deactivating": true, "reloading": true, "unknown": true,
			"enabled": true, "enabled-runtime": true, "disabled": true,
			"static": true, "indirect": true, "generated": true, "transient": true,
			"masked": true, "masked-runtime": true, "linked": true,
			"linked-runtime": true, "alias": true, "not-found": true,
		}
		if !known[value] {
			return "", fmt.Errorf("read %s service state: %w", operation, err)
		}
	}
	return value, nil
}
