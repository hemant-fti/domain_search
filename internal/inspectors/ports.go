package inspectors

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	gonet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint32 `json:"port"`
	State    string `json:"state"`
	PID      int32  `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
}

type Options struct {
	Protocol       string
	State          string
	Port           uint32
	RangeStart     uint32
	RangeEnd       uint32
	PID            int32
	IncludeProcess bool
	All            bool
}

func List(ctx context.Context, options Options) ([]Listener, error) {
	connections, err := gonet.ConnectionsWithContext(ctx, "all")
	if err != nil {
		return nil, fmt.Errorf("list local network connections: %w", err)
	}

	result := make([]Listener, 0)
	processNames := make(map[int32]string)
	for _, connection := range connections {
		protocol := connectionProtocol(connection.Type)
		if protocol == "" || (options.Protocol != "" && protocol != options.Protocol) {
			continue
		}
		if options.Port != 0 && connection.Laddr.Port != options.Port {
			continue
		}
		if options.RangeStart != 0 &&
			(connection.Laddr.Port < options.RangeStart || connection.Laddr.Port > options.RangeEnd) {
			continue
		}
		if options.PID != 0 && connection.Pid != options.PID {
			continue
		}
		if !options.All &&
			(options.State == "" || strings.EqualFold(options.State, "listening")) &&
			!isListening(connection, protocol) {
			continue
		}
		if options.State != "" && !matchesState(connection, protocol, options.State) {
			continue
		}

		listener := Listener{
			Protocol: protocol,
			Address:  connection.Laddr.IP,
			Port:     connection.Laddr.Port,
			State:    strings.ToLower(connection.Status),
			PID:      connection.Pid,
		}
		if listener.State == "" && protocol == "udp" {
			listener.State = "bound"
		}
		if options.IncludeProcess && connection.Pid > 0 {
			name, ok := processNames[connection.Pid]
			if !ok {
				proc, err := process.NewProcessWithContext(ctx, connection.Pid)
				if err != nil {
					return nil, fmt.Errorf("inspect process %d for local port %d: %w", connection.Pid, connection.Laddr.Port, err)
				}
				name, err = proc.NameWithContext(ctx)
				if err != nil {
					return nil, fmt.Errorf("inspect process %d for local port %d: %w", connection.Pid, connection.Laddr.Port, err)
				}
				processNames[connection.Pid] = name
			}
			listener.Process = name
		}
		result = append(result, listener)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		if result[i].Protocol != result[j].Protocol {
			return result[i].Protocol < result[j].Protocol
		}
		return result[i].Address < result[j].Address
	})
	return result, nil
}

func connectionProtocol(connectionType uint32) string {
	switch connectionType {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return ""
	}
}

func isListening(connection gonet.ConnectionStat, protocol string) bool {
	if protocol == "udp" {
		return connection.Raddr.IP == "" && connection.Raddr.Port == 0
	}
	return strings.EqualFold(connection.Status, "LISTEN")
}

func matchesState(connection gonet.ConnectionStat, protocol, state string) bool {
	if protocol == "udp" && strings.EqualFold(state, "listening") {
		return isListening(connection, protocol)
	}
	return strings.EqualFold(connection.Status, state)
}

var listen = regexp.MustCompile(`(?m)^[ \t]*listen[ \t]+([^;]+);`)

func ParsePorts(block string) []int {
	var ports []int
	seen := make(map[int]bool)

	for _, match := range listen.FindAllStringSubmatch(block, -1) {
		if len(match) < 2 {
			continue
		}

		fields := strings.Fields(match[1])
		if len(fields) == 0 {
			continue
		}

		address := fields[0]
		portText := address

		if strings.HasPrefix(address, "unix:") {
			continue
		}

		if strings.HasPrefix(address, "[") {
			end := strings.LastIndex(address, "]")
			if end == -1 || end+1 >= len(address) || address[end+1] != ':' {
				continue
			}
			portText = address[end+2:]
		} else if index := strings.LastIndex(address, ":"); index >= 0 {
			portText = address[index+1:]
		} else {
			portText = address
		}

		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || seen[port] {
			continue
		}

		seen[port] = true
		ports = append(ports, port)
	}

	sort.Ints(ports)
	return ports
}
