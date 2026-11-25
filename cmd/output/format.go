package output

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"

	"domain-search/models"
)

// ---------- options & styling ----------

// Options controls how the human-readable report is rendered.
type Options struct {
	Verbose bool // show config paths, proxy targets, aliases, IIS details
	ASCII   bool // force ASCII symbols (legacy consoles, log files)
}

type symbols struct {
	ok, warn, fail, up, down, full, empty, ellipsis, dash, rule string
}

var unicodeSymbols = symbols{
	ok: "✔", warn: "⚠", fail: "✖", up: "●", down: "○",
	full: "█", empty: "░", ellipsis: "…", dash: "—", rule: "─",
}

type styleFunc func(a ...interface{}) string

var (
	bold   = color.New(color.Bold).SprintFunc()
	dim    = color.New(color.Faint).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	cyan   = color.New(color.FgCyan, color.Bold).SprintFunc()
)

// ---------- value formatting ----------

const notReported = "Not reported"

func DisplayValue(value string) string {
	if value = strings.TrimSpace(value); value == "" {
		return notReported
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
	for i, p := range ports {
		values[i] = strconv.Itoa(p)
	}
	return "[" + strings.Join(values, ", ") + "]"
}

func formatCount(value int) string {
	if value <= 0 {
		return notReported
	}
	return strconv.Itoa(value)
}

func formatStorage(value float64) string {
	if value <= 0 {
		return notReported
	}
	return fmt.Sprintf("%.2f GiB", value)
}

func FormatUptime(seconds uint64) string {
	const (
		minute = 60
		hour   = 60 * minute
		day    = 24 * hour
	)

	var parts []string
	if d := seconds / day; d > 0 {
		parts = append(parts, countWithUnit(d, "day"))
	}
	if h := (seconds % day) / hour; h > 0 {
		parts = append(parts, countWithUnit(h, "hour"))
	}
	if m := (seconds % hour) / minute; m > 0 {
		parts = append(parts, countWithUnit(m, "minute"))
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

func cpuSummary(model string, cores, threads int) string {
	model = DisplayValue(model)
	if cores <= 0 || threads <= 0 {
		return model
	}
	return fmt.Sprintf("%s (%d cores / %d threads)", model, cores, threads)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, v)
	}
	return result
}

func FormatDomain(d models.Domain) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Domain: %s\n", DisplayValue(d.Name))
	fmt.Fprintf(&b, "Server: %s\n", DisplayValue(d.Source))
	fmt.Fprintf(&b, "Configuration: %s\n", DisplayValue(d.ConfigPath))
	fmt.Fprintf(&b, "Proxy Target: %s\n", DisplayValue(d.ProxyTarget))
	fmt.Fprintf(&b, "SSL Certificate: %s\n", DisplayValue(d.SSLCertificate))
	fmt.Fprintf(&b, "Aliases: %s\n", DisplayList(d.Aliases))
	fmt.Fprintf(&b, "Ports: %s\n", DisplayPorts(d.Ports))
	return b.String()
}

// ---------- table & bar primitives ----------

const colGap = 3

// cell holds styled text plus its plain form, so column widths are
// computed from visible characters rather than ANSI escape codes.
type cell struct {
	styled string
	plain  string
}

func plain(s string) cell { return cell{styled: s, plain: s} }

func (c cell) width() int { return utf8.RuneCountInString(c.plain) }

func truncate(s string, max int, ellipsis string) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	keep := max - utf8.RuneCountInString(ellipsis)
	if keep < 0 {
		keep = 0
	}
	return string(runes[:keep]) + ellipsis
}

func writeTable(w io.Writer, header []string, rows [][]cell) {
	headerCells := make([]cell, len(header))
	for i, h := range header {
		headerCells[i] = cell{dim(h), h}
	}

	widths := make([]int, len(header))
	for _, row := range append([][]cell{headerCells}, rows...) {
		for i, c := range row {
			if n := c.width(); n > widths[i] {
				widths[i] = n
			}
		}
	}

	line := func(cells []cell) {
		var b strings.Builder
		for i, c := range cells {
			b.WriteString(c.styled)
			b.WriteString(strings.Repeat(" ", widths[i]-c.width()+colGap))
		}
		fmt.Fprintf(w, "  %s\n", strings.TrimRight(b.String(), " "))
	}

	line(headerCells)
	for _, row := range rows {
		line(row)
	}
}

func usageBar(used, total float64, width int, sym symbols) string {
	if total <= 0 {
		return dim("n/a")
	}

	pct := math.Min(math.Max(used/total*100, 0), 100)
	filled := int(pct / 100 * float64(width))
	bar := strings.Repeat(sym.full, filled) + strings.Repeat(sym.empty, width-filled)

	return fmt.Sprintf("%s %3.0f%%", usageStyle(pct)(bar), pct)
}

func usageStyle(pct float64) styleFunc {
	switch {
	case pct >= 90:
		return red
	case pct >= 75:
		return yellow
	default:
		return green
	}
}
