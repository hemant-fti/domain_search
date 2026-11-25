package output

import (
	"domain-search/models"
	"domain-search/pkg/system"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func DisplayValue(value string) string {
	value = strings.TrimSpace(value)

	if value == "" {
		return "Not reported"
	}

	return value
}

func DisplayList(values []string) string {
	if len(values) == 0 {
		return "None reported"
	}

	return strings.Join(values, ", ")
}

func DisplayPorts(ports []int) string {
	if len(ports) == 0 {
		return "None reported"
	}

	values := make([]string, len(ports))

	for index, port := range ports {
		values[index] = strconv.Itoa(port)
	}

	return "[" + strings.Join(values, ", ") + "]"
}

func formatCount(value int) string {
	if value <= 0 {
		return "Not reported"
	}

	return strconv.Itoa(value)
}

func formatStorage(value float64) string {
	if value <= 0 {
		return "Not reported"
	}

	return fmt.Sprintf("%.2f GiB", value)
}

func FormatUptime(seconds uint64) string {
	const (
		secondsPerDay  = 86400
		secondsPerHour = 3600
		secondsPerMin  = 60
	)

	days := seconds / secondsPerDay
	hours := seconds % secondsPerDay / secondsPerHour
	minutes := seconds % secondsPerHour / secondsPerMin

	var parts []string

	if days > 0 {
		parts = append(parts, countWithUnit(days, "day"))
	}

	if hours > 0 {
		parts = append(parts, countWithUnit(hours, "hour"))
	}

	if minutes > 0 {
		parts = append(parts, countWithUnit(minutes, "minute"))
	}

	if len(parts) == 0 {
		return "Less than a minute"
	}

	return strings.Join(parts, ", ")
}

func countWithUnit(count uint64, unit string) string {
	if count != 1 {
		unit += "s"
	}

	return fmt.Sprintf("%d %s", count, unit)
}

func scanStatusLabel(status string) string {
	switch strings.ToLower(status) {
	case "completed", "success", "successful":
		return "COMPLETED"

	case "completed_with_warnings":
		return "COMPLETED WITH WARNINGS"

	case "failed", "error":
		return "FAILED"

	default:
		return DisplayValue(status)
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		key := strings.ToLower(value)

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		result = append(result, value)
	}

	return result
}

func writeProcessMemory(w io.Writer) {
	memory := system.GetProcessMemory()

	section(w, "PROCESS MEMORY")

	kv(w, 2, keyWidth, "Heap allocated",
		fmt.Sprintf("%.2f MB", memory.AllocMB))

	kv(w, 2, keyWidth, "Total allocated",
		fmt.Sprintf("%.2f MB", memory.TotalAllocMB))

	kv(w, 2, keyWidth, "Runtime memory",
		fmt.Sprintf("%.2f MB", memory.SysMB))

	kv(w, 2, keyWidth, "Heap reserved",
		fmt.Sprintf("%.2f MB", memory.HeapSysMB))

	fmt.Fprintln(w)
}

func FormatDomain(domain models.Domain) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Domain: %s\n", DisplayValue(domain.Name))
	fmt.Fprintf(&b, "Server: %s\n", DisplayValue(domain.Source))
	fmt.Fprintf(&b, "Configuration: %s\n", DisplayValue(domain.ConfigPath))
	fmt.Fprintf(&b, "Proxy Target: %s\n", DisplayValue(domain.ProxyTarget))
	fmt.Fprintf(&b, "SSL Certificate: %s\n", DisplayValue(domain.SSLCertificate))
	fmt.Fprintf(&b, "Aliases: %s\n", DisplayList(domain.Aliases))
	fmt.Fprintf(&b, "Ports: %s\n", DisplayPorts(domain.Ports))

	return b.String()
}
