package output

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"

	"domain-search/internal/discovery"
	"domain-search/models"
)

// Options controls how the human-readable report is rendered.
type Options struct {
	Verbose bool // show config paths, doc roots, proxy targets, aliases
	ASCII   bool // force ASCII symbols (legacy consoles, log files)
}

type symbols struct {
	ok, warn, fail, up, down, full, empty, ellipsis, dash string
}

var (
	unicodeSymbols = symbols{"✔", "⚠", "✖", "●", "○", "█", "░", "…", "—"}
)

var (
	bold   = color.New(color.Bold).SprintFunc()
	dim    = color.New(color.Faint).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	cyan   = color.New(color.FgCyan, color.Bold).SprintFunc()
)

type styleFunc func(a ...interface{}) string

const (
	ruleWidth    = 64
	keyWidth     = 16
	maxDomainLen = 38
)

// WriteHuman renders a human-readable scan report. It only formats;
// persisting the result is the caller's responsibility.
func WriteHuman(out io.Writer, result models.Result) error {
	var b strings.Builder

	writeHeader(&b, result, unicodeSymbols)
	counts := dnsCounts(result)
	writeSummary(&b, result, counts, unicodeSymbols)
	writeWarnings(&b, result, unicodeSymbols)
	writeServices(&b, result, unicodeSymbols)
	writeWebsites(&b, result, unicodeSymbols)
	writeSystem(&b, result, unicodeSymbols)

	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write human-readable output: %w", err)
	}

	return nil
}

// ---------- sections ----------

func writeHeader(w io.Writer, r models.Result, sym symbols) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  %s\n", cyan("hostscope"), dim("· Server Discovery Report"))
	fmt.Fprintf(w, "  %s\n", dim(strings.Repeat(rule(sym), ruleWidth)))

	host := DisplayValue(r.Server.Hostname)
	ip := DisplayValue(r.Server.PrimaryIP)
	fmt.Fprintf(w, "  %s %s %s\n", bold(host), dim("·"), ip)

	meta := "Status: " + scanStatusLabel(r.Status)
	if !r.ScannedAt.IsZero() {
		meta += "  ·  " + r.ScannedAt.Format("02 Jan 2006, 03:04 PM MST")
	}
	fmt.Fprintf(w, "  %s\n\n", dim(meta))
}

type dnsTally struct{ matched, elsewhere, unresolved int }

func dnsCounts(r models.Result) dnsTally {
	var t dnsTally
	for _, d := range r.Domains {
		switch d.DNS.Status {
		case "matches_server":
			t.matched++
		case "resolved_other_ip":
			t.elsewhere++
		case "unresolved":
			t.unresolved++
		}
	}
	return t
}

func writeSummary(w io.Writer, r models.Result, t dnsTally, sym symbols) {
	total := len(r.Domains)
	if r.TotalDomains > total {
		total = r.TotalDomains
	}

	section(w, "SUMMARY")

	parts := []string{
		fmt.Sprintf("%s %d websites", dim(sym.dash), total),
		fmt.Sprintf("%s %d DNS match", green(sym.ok), t.matched),
	}
	if t.elsewhere > 0 {
		parts = append(parts, fmt.Sprintf("%s %d point elsewhere", yellow(sym.warn), t.elsewhere))
	}
	if t.unresolved > 0 {
		parts = append(parts, fmt.Sprintf("%s %d unresolved", red(sym.fail), t.unresolved))
	}
	fmt.Fprintf(w, "  %s\n\n", strings.Join(parts, "   "))
}

func writeWarnings(w io.Writer, r models.Result, sym symbols) {
	if len(r.Warnings) == 0 {
		return
	}

	section(w, fmt.Sprintf("WARNINGS (%d)", len(r.Warnings)))
	for _, warning := range r.Warnings {
		msg := discovery.FriendlyErrorMessage(fmt.Errorf("%s", warning), "")
		fmt.Fprintf(w, "  %s %s\n", yellow(sym.warn), msg)
	}
	fmt.Fprintln(w)
}

func writeServices(w io.Writer, r models.Result, sym symbols) {
	section(w, "SERVICES")

	if len(r.Servers) == 0 {
		fmt.Fprintf(w, "  %s\n\n", dim("No web server services detected."))
		return
	}

	nameWidth := 0
	for _, s := range r.Servers {
		if n := utf8.RuneCountInString(DisplayValue(s.Server)); n > nameWidth {
			nameWidth = n
		}
	}

	for _, s := range r.Servers {
		name := DisplayValue(s.Server)
		pad := strings.Repeat(" ", nameWidth-utf8.RuneCountInString(name))
		if s.Running {
			fmt.Fprintf(w, "  %s%s  %s %s\n", name, pad, green(sym.up), green("running"))
		} else {
			fmt.Fprintf(w, "  %s%s  %s %s\n", name, pad, dim(sym.down), dim("not running"))
		}
	}
	fmt.Fprintln(w)
}

func writeWebsites(w io.Writer, r models.Result, sym symbols) {
	section(w, fmt.Sprintf("WEBSITES (%d)", len(r.Domains)))

	if len(r.Domains) == 0 {
		fmt.Fprintf(w, "  %s\n\n", dim("No website configurations were discovered."))
		return
	}

	header := []string{"DOMAIN / WEBSITE", "SERVER", "PORTS", "SSL", "DNS"}
	rows := make([][]cell, 0, len(r.Domains))

	for _, d := range r.Domains {
		ssl := cell{dim(sym.dash), sym.dash}
		if strings.TrimSpace(d.SSLCertificate) != "" {
			ssl = cell{green(sym.ok), sym.ok}
		}

		displayName := d.Name
		if strings.EqualFold(d.Source, "iis") {
			if strings.TrimSpace(displayName) == "" {
				displayName = d.WebsiteName
			}
		}

		rows = append(rows, []cell{
			plain(truncate(DisplayValue(displayName), maxDomainLen, sym.ellipsis)),
			plain(DisplayValue(d.Source)),
			plain(displayPorts(d.Ports)),
			ssl,
			dnsCell(d.DNS.Status, sym),
		})
	}

	// Always display the website table.
	writeTable(w, header, rows)

	// Display detailed website information.
	for _, d := range r.Domains {
		displayName := d.Name
		if strings.EqualFold(d.Source, "iis") && strings.TrimSpace(displayName) == "" {
			displayName = d.WebsiteName
		}

		fmt.Fprintf(w, "\n  %s\n", bold(DisplayValue(displayName)))

		if strings.EqualFold(d.Source, "iis") {
			kv(w, 4, 18, "Website ID", DisplayValue(d.ID))
			kv(w, 4, 18, "Website name", DisplayValue(d.WebsiteName))
			kv(w, 4, 18, "Status", DisplayValue(d.Status))
			kv(w, 4, 18, "Hostname", DisplayValue(d.Hostname))
			kv(w, 4, 18, "Bindings", DisplayList(uniqueStrings(d.Binding)))
			kv(w, 4, 18, "Physical path", DisplayValue(d.Path))
		}

		kv(w, 4, 18, "Config file", DisplayValue(d.ConfigPath))
		kv(w, 4, 18, "Proxy target", DisplayValue(d.ProxyTarget))
		kv(w, 4, 18, "SSL certificate", DisplayValue(d.SSLCertificate))
		kv(w, 4, 18, "Aliases", DisplayList(d.Aliases))
	}

	fmt.Fprintln(w)
}

func truncate(s string, max int, ellipsis string) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}

	runes := []rune(s)
	return string(runes[:max-utf8.RuneCountInString(ellipsis)]) + ellipsis
}

// cell holds styled text and its plain representation.
type cell struct {
	styled string
	plain  string
}

func plain(s string) cell {
	return cell{
		styled: s,
		plain:  s,
	}
}

func dnsCell(status string, sym symbols) cell {
	switch status {
	case "matches_server":
		return cell{green(sym.ok + " matches"), sym.ok + " matches"}
	case "resolved_other_ip":
		return cell{yellow(sym.warn + " points elsewhere"), sym.warn + " points elsewhere"}
	case "unresolved":
		return cell{red(sym.fail + " unresolved"), sym.fail + " unresolved"}
	default:
		return cell{dim(sym.dash), sym.dash}
	}
}

func writeTable(w io.Writer, header []string, rows [][]cell) {
	widths := make([]int, len(header))

	for i, h := range header {
		widths[i] = utf8.RuneCountInString(h)
	}

	for _, row := range rows {
		for i, c := range row {
			if n := utf8.RuneCountInString(c.plain); n > widths[i] {
				widths[i] = n
			}
		}
	}

	var line strings.Builder

	for i, h := range header {
		line.WriteString(dim(h))
		line.WriteString(strings.Repeat(
			" ",
			widths[i]-utf8.RuneCountInString(h)+3,
		))
	}

	fmt.Fprintf(w, "  %s\n", strings.TrimRight(line.String(), " "))

	for _, row := range rows {
		line.Reset()

		for i, c := range row {
			line.WriteString(c.styled)
			line.WriteString(strings.Repeat(
				" ",
				widths[i]-utf8.RuneCountInString(c.plain)+3,
			))
		}

		fmt.Fprintf(w, "  %s\n", strings.TrimRight(line.String(), " "))
	}
}

func writeSystem(w io.Writer, r models.Result, sym symbols) {
	s := r.System

	section(w, "SYSTEM")

	osName := strings.TrimSpace(s.ServerOS)
	osVersion := strings.TrimSpace(s.OSVersion)

	if osName == "" {
		osName = strings.TrimSpace(r.Server.OperatingSystem)
	}

	kv(w, 2, keyWidth, "OS", DisplayValue(osName))
	kv(w, 2, keyWidth, "Version", DisplayValue(osVersion))
	kv(w, 2, keyWidth, "Architecture", DisplayValue(s.Architecture))

	kv(w, 2, keyWidth, "CPU", fmt.Sprintf("%s (%s cores / %s threads)",
		DisplayValue(s.CPUModel),
		formatCount(s.Cores),
		formatCount(s.Threads),
	))

	kv(w, 2, keyWidth, "Uptime", FormatUptime(s.Uptime))
	kv(w, 2, keyWidth, "User", DisplayValue(s.CurrentUser))
	kv(w, 2, keyWidth, "Time zone", DisplayValue(s.Timezone))
	kv(w, 2, keyWidth, "IPv4", DisplayList(s.IPv4))
	kv(w, 2, keyWidth, "IPv6", DisplayList(s.IPv6))
	kv(w, 2, keyWidth, "MAC", DisplayValue(s.MAC))

	fmt.Fprintln(w)

	fmt.Fprintf(w, "  %-*s %s  %s / %s\n", keyWidth-2, "Disk",
		usageBar(s.Disk.UsedGB, s.Disk.TotalGB, 20, sym),
		formatStorage(s.Disk.UsedGB),
		formatStorage(s.Disk.TotalGB),
	)

	fmt.Fprintf(w, "  %-*s %s  %s / %s\n", keyWidth-2, "Memory",
		usageBar(s.Memory.UsedGB, s.Memory.TotalGB, 20, sym),
		formatStorage(s.Memory.UsedGB),
		formatStorage(s.Memory.TotalGB),
	)

	fmt.Fprintln(w)
}

// ---------- building blocks ----------

func section(w io.Writer, title string) {
	fmt.Fprintf(w, "  %s\n", cyan(title))
}

func rule(sym symbols) string {
	if sym.ok == "+" {
		return "-"
	}
	return "─"
}

func kv(w io.Writer, indent, width int, key, value string) {
	fmt.Fprintf(w, "%s%s %s\n",
		strings.Repeat(" ", indent),
		dim(fmt.Sprintf("%-*s", width, key)),
		value)
}

// cell holds styled text plus its plain form, so column widths are
// computed from visible characters rather than ANSI escape codes.

type number interface {
	~int | ~int64 | ~float32 | ~float64
}

func usageBar[T number](used, total T, width int, sym symbols) string {
	if total <= 0 {
		return dim("n/a")
	}

	pct := float64(used) / float64(total) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}

	filled := int(pct / 100 * float64(width))
	bar := strings.Repeat(sym.full, filled) + strings.Repeat(sym.empty, width-filled)

	style := styleFunc(green)
	switch {
	case pct >= 90:
		style = red
	case pct >= 75:
		style = yellow
	}

	return fmt.Sprintf("%s %3.0f%%", style(bar), pct)
}
