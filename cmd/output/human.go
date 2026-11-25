package output

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"domain-search/internal/discovery"
	"domain-search/models"
	"domain-search/pkg/system"
)

const (
	ruleWidth      = 64
	keyWidth       = 16
	detailIndent   = 4
	detailKeyWidth = 18
	barWidth       = 20
	maxDomainLen   = 38
)

// DNS statuses. Move these into package models so producer and renderer share them.
const (
	dnsMatches    = "matches_server"
	dnsElsewhere  = "resolved_other_ip"
	dnsUnresolved = "unresolved"
	dnsInvalidIP  = "invalid_server_ip"
)

type renderer struct {
	w   io.Writer
	sym symbols
}

func newRenderer(w io.Writer) *renderer {
	return &renderer{w: w, sym: unicodeSymbols}
}

// render builds the report in memory and writes it once, so callers get a
// real error instead of a half-written report.
func render(out io.Writer, build func(*renderer)) error {
	var b strings.Builder
	build(newRenderer(&b))

	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// ---------- public API ----------

// WriteHuman renders the full scan report. It only formats; persisting
// the result is the caller's responsibility.
func WriteHuman(out io.Writer, result models.Result) error {
	return render(out, func(r *renderer) {
		r.header(result)
		r.summary(totalDomains(result), dnsCounts(result.Domains))
		r.warnings(result.Warnings)
		r.services(result)
		r.websites(result.Domains)
		r.system(result)
		r.processMemory()
	})
}

func WriteDomains(out io.Writer, domains []models.Domain) error {
	results := make([]models.DomainResult, len(domains))
	for i, d := range domains {
		results[i] = models.DomainResult{Domain: d}
	}

	return render(out, func(r *renderer) {
		r.commandHeader("Server Discovery Report")
		r.summary(len(results), dnsCounts(results))
		r.websites(results)
	})
}

func WriteCPU(out io.Writer, info models.CPUInfo) error {
	return render(out, func(r *renderer) {
		r.commandHeader("System Information")
		r.cpu(info.Model, info.Cores, info.Threads)
	})
}

func WriteMemory(out io.Writer, info models.MemoryInfo) error {
	return render(out, func(r *renderer) {
		r.commandHeader("System Information")
		r.memory(info)
	})
}

func WriteUptime(out io.Writer, seconds uint64) error {
	return render(out, func(r *renderer) {
		r.commandHeader("System Information")
		r.uptime(seconds)
	})
}

func WriteDisk(out io.Writer, info models.DiskInfo) error {
	return render(out, func(r *renderer) {
		r.commandHeader("System Information")
		r.disk(info)
	})
}

// WriteSystem renders the full system report.
func WriteSystem(out io.Writer, info models.SystemInfo) error {
	return render(out, func(r *renderer) {
		r.commandHeader("System Information")
		r.systemInfo(info, "")
		r.processMemory()
	})
}

// ---------- building blocks ----------

func (r *renderer) section(title string) {
	fmt.Fprintf(r.w, "  %s\n", cyan(title))
}

func (r *renderer) kv(indent, width int, key, value string) {
	fmt.Fprintf(r.w, "%s%s %s\n",
		strings.Repeat(" ", indent), dim(fmt.Sprintf("%-*s", width, key)), value)
}

func (r *renderer) title(title string) {
	fmt.Fprintf(r.w, "  %s  %s\n", cyan("hostscope"), dim("· "+title))
	fmt.Fprintf(r.w, "  %s\n", dim(strings.Repeat(r.sym.rule, ruleWidth)))
}

func (r *renderer) commandHeader(title string) {
	fmt.Fprintln(r.w)
	r.title(title)
	fmt.Fprintln(r.w)
}

// ---------- scan report sections ----------

func (r *renderer) header(res models.Result) {
	fmt.Fprintln(r.w)
	r.title("Server Discovery Report")

	fmt.Fprintf(r.w, "  %s %s %s\n",
		bold(DisplayValue(res.Server.Hostname)), dim("·"), DisplayValue(res.Server.PrimaryIP))

	meta := "Status: " + scanStatusLabel(res.Status)
	if !res.ScannedAt.IsZero() {
		meta += "  ·  " + res.ScannedAt.Format("02 Jan 2006, 03:04 PM MST")
	}
	fmt.Fprintf(r.w, "  %s\n\n", dim(meta))
}

type dnsTally struct{ matched, elsewhere, unresolved, invalid int }

func (t dnsTally) checked() int {
	return t.matched + t.elsewhere + t.unresolved + t.invalid
}

func dnsCounts(domains []models.DomainResult) dnsTally {
	var t dnsTally
	for _, d := range domains {
		switch d.DNS.Status {
		case dnsMatches:
			t.matched++
		case dnsElsewhere:
			t.elsewhere++
		case dnsUnresolved:
			t.unresolved++
		case dnsInvalidIP:
			t.invalid++
		}
	}
	return t
}

func totalDomains(res models.Result) int {
	return max(len(res.Domains), res.TotalDomains)
}

func (r *renderer) summary(total int, t dnsTally) {
	r.section("SUMMARY")

	parts := []string{fmt.Sprintf("%s %d websites", dim(r.sym.dash), total)}
	if t.checked() > 0 { // skip DNS stats when no DNS lookup ran
		parts = append(parts, fmt.Sprintf("%s %d DNS match", green(r.sym.ok), t.matched))
	}
	if t.elsewhere > 0 {
		parts = append(parts, fmt.Sprintf("%s %d point elsewhere", yellow(r.sym.warn), t.elsewhere))
	}
	if t.unresolved > 0 {
		parts = append(parts, fmt.Sprintf("%s %d unresolved", red(r.sym.fail), t.unresolved))
	}
	if t.invalid > 0 {
		parts = append(parts, fmt.Sprintf("%s %d not verified", yellow(r.sym.warn), t.invalid))
	}
	fmt.Fprintf(r.w, "  %s\n\n", strings.Join(parts, "   "))
}

func (r *renderer) warnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}

	r.section(fmt.Sprintf("WARNINGS (%d)", len(warnings)))
	for _, w := range warnings {
		msg := discovery.FriendlyErrorMessage(errors.New(w), "")
		fmt.Fprintf(r.w, "  %s %s\n", yellow(r.sym.warn), msg)
	}
	fmt.Fprintln(r.w)
}

func (r *renderer) services(res models.Result) {
	r.section("SERVICES")

	if len(res.Servers) == 0 {
		fmt.Fprintf(r.w, "  %s\n\n", dim("No web server services detected."))
		return
	}

	width := 0
	for _, s := range res.Servers {
		width = max(width, len([]rune(DisplayValue(s.Server))))
	}

	for _, s := range res.Servers {
		name := fmt.Sprintf("%-*s", width, DisplayValue(s.Server))
		if s.Running {
			fmt.Fprintf(r.w, "  %s  %s %s\n", name, green(r.sym.up), green("running"))
		} else {
			fmt.Fprintf(r.w, "  %s  %s %s\n", name, dim(r.sym.down), dim("not running"))
		}
	}
	fmt.Fprintln(r.w)
}

func domainName(d models.DomainResult) string {
	if strings.EqualFold(d.Source, "iis") && strings.TrimSpace(d.Name) == "" {
		return d.WebsiteName
	}
	return d.Name
}

func (r *renderer) websites(domains []models.DomainResult) {
	r.section(fmt.Sprintf("WEBSITES (%d)", len(domains)))

	if len(domains) == 0 {
		fmt.Fprintf(r.w, "  %s\n\n", dim("No website configurations were discovered."))
		return
	}

	header := []string{"DOMAIN / WEBSITE", "SERVER", "PORTS", "SSL", "DNS"}
	rows := make([][]cell, 0, len(domains))

	for _, d := range domains {
		ssl := cell{dim(r.sym.dash), r.sym.dash}
		if strings.TrimSpace(d.SSLCertificate) != "" {
			ssl = cell{green(r.sym.ok), r.sym.ok}
		}

		rows = append(rows, []cell{
			plain(truncate(DisplayValue(domainName(d)), maxDomainLen, r.sym.ellipsis)),
			plain(DisplayValue(d.Source)),
			plain(DisplayPorts(d.Ports)),
			ssl,
			r.dnsCell(d.DNS.Status),
		})
	}
	writeTable(r.w, header, rows)

	for _, d := range domains {
		r.websiteDetails(d)
	}
	fmt.Fprintln(r.w)
}

func (r *renderer) websiteDetails(d models.DomainResult) {
	fmt.Fprintf(r.w, "\n  %s\n", bold(DisplayValue(domainName(d))))

	kv := func(key, value string) { r.kv(detailIndent, detailKeyWidth, key, value) }

	if strings.EqualFold(d.Source, "iis") {
		kv("Website ID", DisplayValue(d.ID))
		kv("Website name", DisplayValue(d.WebsiteName))
		kv("Status", DisplayValue(d.Status))
		kv("Hostname", DisplayValue(d.Hostname))
		kv("Bindings", DisplayList(uniqueStrings(d.Binding)))
		kv("Physical path", DisplayValue(d.Path))
	}
	kv("Config file", DisplayValue(d.ConfigPath))
	kv("Proxy target", DisplayValue(d.ProxyTarget))
	kv("SSL certificate", DisplayValue(d.SSLCertificate))
	kv("Aliases", DisplayList(d.Aliases))
}

func (r *renderer) dnsCell(status string) cell {
	s := r.sym
	switch status {
	case dnsMatches:
		return cell{green(s.ok + " matches"), s.ok + " matches"}
	case dnsElsewhere:
		return cell{yellow(s.warn + " points elsewhere"), s.warn + " points elsewhere"}
	case dnsUnresolved:
		return cell{red(s.fail + " unresolved"), s.fail + " unresolved"}
	case dnsInvalidIP:
		return cell{yellow(s.warn + " not verified"), s.warn + " not verified"}
	default:
		return cell{dim(s.dash), s.dash}
	}
}

// ---------- system sections ----------

func (r *renderer) system(res models.Result) {
	r.systemInfo(res.System, res.Server.OperatingSystem)
}

func (r *renderer) systemInfo(s models.SystemInfo, fallbackOS string) {
	osName := strings.TrimSpace(s.ServerOS)
	if osName == "" {
		osName = strings.TrimSpace(fallbackOS)
	}

	r.section("SYSTEM")
	kv := func(key, value string) { r.kv(2, keyWidth, key, value) }

	kv("Hostname", DisplayValue(s.Hostname))
	kv("OS", DisplayValue(osName))
	kv("Version", DisplayValue(s.OSVersion))
	kv("Kernel", DisplayValue(s.Kernel))
	kv("Architecture", DisplayValue(s.Architecture))
	kv("CPU", cpuSummary(s.CPUModel, s.Cores, s.Threads))
	kv("Uptime", FormatUptime(s.Uptime))
	kv("User", DisplayValue(s.CurrentUser))
	kv("Time zone", DisplayValue(s.Timezone))
	kv("IPv4", DisplayList(s.IPv4))
	kv("IPv6", DisplayList(s.IPv6))
	kv("MAC", DisplayValue(s.MAC))
	fmt.Fprintln(r.w)

	r.usageLine("Disk", s.Disk.UsedGB, s.Disk.TotalGB)
	r.usageLine("Memory", s.Memory.UsedGB, s.Memory.TotalGB)
	fmt.Fprintln(r.w)
}

func (r *renderer) usageLine(label string, used, total float64) {
	fmt.Fprintf(r.w, "  %-*s %s  %s / %s\n", keyWidth-2, label,
		usageBar(used, total, barWidth, r.sym), formatStorage(used), formatStorage(total))
}

func (r *renderer) cpu(model string, cores, threads int) {
	r.section("CPU")
	r.kv(2, keyWidth, "Model", DisplayValue(model))
	r.kv(2, keyWidth, "Cores", formatCount(cores))
	r.kv(2, keyWidth, "Threads", formatCount(threads))
	fmt.Fprintln(r.w)
}

func (r *renderer) memory(info models.MemoryInfo) {
	r.section("MEMORY")
	r.kv(2, keyWidth, "Total", formatStorage(info.TotalGB))
	r.kv(2, keyWidth, "Used", formatStorage(info.UsedGB))
	r.kv(2, keyWidth, "Available", formatStorage(info.AvailableGB))
	r.kv(2, keyWidth, "Free", formatStorage(info.FreeGB))
	fmt.Fprintln(r.w)
	r.processMemory()
}

func (r *renderer) disk(info models.DiskInfo) {
	r.section("DISK")
	r.kv(2, keyWidth, "Total", formatStorage(info.TotalGB))
	r.kv(2, keyWidth, "Used", formatStorage(info.UsedGB))
	r.kv(2, keyWidth, "Available", formatStorage(info.AvailableGB))
	r.kv(2, keyWidth, "Free", formatStorage(info.FreeGB))
	fmt.Fprintln(r.w)
}

func (r *renderer) uptime(seconds uint64) {
	r.section("UPTIME")
	r.kv(2, keyWidth, "Uptime", FormatUptime(seconds))
	fmt.Fprintln(r.w)
}

func (r *renderer) processMemory() {
	m := system.GetProcessMemory()

	r.section("PROCESS MEMORY")
	r.kv(2, keyWidth, "Heap allocated", fmt.Sprintf("%.2f MB", m.AllocMB))
	r.kv(2, keyWidth, "Total allocated", fmt.Sprintf("%.2f MB", m.TotalAllocMB))
	r.kv(2, keyWidth, "Runtime memory", fmt.Sprintf("%.2f MB", m.SysMB))
	r.kv(2, keyWidth, "Heap reserved", fmt.Sprintf("%.2f MB", m.HeapSysMB))
	fmt.Fprintln(r.w)
}
