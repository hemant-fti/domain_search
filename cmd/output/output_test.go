package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"domain-search/internal/discovery"
	"domain-search/internal/dns"
	"domain-search/internal/inspectors"
	"domain-search/internal/server"
)

func TestWriteHumanIncludesDiscoveryFields(t *testing.T) {
	dir := t.TempDir()
	originalResultsPath := ScanResultsFile
	originalErrorsPath := ScanErrorsFile
	ScanResultsFile = filepath.Join(t.TempDir(), "scan-results.jsonl")
	ScanErrorsFile = filepath.Join(dir, "scan-errors.jsonl")
	t.Cleanup(func() {
		ScanResultsFile = originalResultsPath
		ScanErrorsFile = originalErrorsPath
	})

	result := discovery.Result{
		ScanResponse: discovery.ScanResponse{
			Servers: []discovery.ServerInfo{{
				Server:  "nginx",
				Running: true,
				Domains: []discovery.DomainInfo{{
					Domain:       "example.com",
					Aliases:      []string{"www.example.com"},
					ConfigFile:   "/etc/nginx/sites-enabled/example",
					DocumentRoot: "/var/www/example",
					Ports:        []int{80, 443},
				}},
			}},
			System: server.SystemInfo{
				Hostname:     "web-01",
				IPv4:         []string{"192.0.2.10"},
				IPv6:         []string{"2001:db8::10"},
				MAC:          "00:11:22:33:44:55",
				ServerOS:     "Linux",
				OSVersion:    "Ubuntu 24.04",
				Architecture: "x86_64",
				Cores:        4,
				Threads:      8,
				CPUModel:     "Example CPU",
				Kernel:       "6.8.0",
				Uptime:       90061,
				CurrentUser:  "admin",
				Timezone:     "UTC",
				Disk:         server.DiskInfo{TotalGB: 100, FreeGB: 40, UsedGB: 60},
				Memory:       server.MemoryInfo{TotalGB: 16, AvailableGB: 8, FreeGB: 4, UsedGB: 8},
			},
		},
		Status:    "completed",
		ScannedAt: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
		Server: server.Info{
			Hostname:        "web-01",
			OperatingSystem: "Ubuntu 24.04",
			Kernel:          "6.8.0",
			PrimaryIP:       "192.0.2.10",
		},
		DetectedServices: []string{"nginx"},
		TotalDomains:     1,
		Domains: []discovery.DomainResult{{
			Domain: inspectors.Domain{
				Name:           "example.com",
				Source:         "nginx",
				ConfigPath:     "/etc/nginx/sites-enabled/example",
				DocumentRoot:   "/var/www/example",
				ProxyTarget:    "http://127.0.0.1:8080",
				SSLCertificate: "/etc/letsencrypt/live/example.com/fullchain.pem",
				Aliases:        []string{"www.example.com"},
				Ports:          []int{80, 443},
			},
			DNS: dns.Result{
				ResolvedIPs:   []string{"192.0.2.10"},
				MatchesServer: true,
				Status:        "matches_server",
			},
		}},
		Warnings: []string{"Some metrics were unavailable"},
	}

	var output bytes.Buffer
	if err := WriteHuman(&output, result); err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	normalizedOutput := strings.Join(strings.Fields(output.String()), " ")
	for _, field := range []string{
		"Listening ports : [80, 443]",
		"SSL certificate : /etc/letsencrypt/live/example.com/fullchain.pem",
		"DNS matches : 1",
		"Some system information could not be collected.",
	} {
		if !strings.Contains(normalizedOutput, field) {
			t.Errorf("human-readable output does not contain %q", field)
		}
	}

	websiteReport := strings.SplitN(output.String(), "Website 1:", 2)
	if len(websiteReport) != 2 {
		t.Fatal("human-readable output does not contain website report")
	}
	websiteReport = strings.SplitN(websiteReport[1], separator, 2)
	for _, field := range []string{"DNS status", "DNS addresses", "Points to this server"} {
		if strings.Contains(websiteReport[0], field) {
			t.Errorf("website report contains removed DNS field %q", field)
		}
	}
}

func TestWriteWarningsHidesTechnicalDetails(t *testing.T) {
	const technical = "nginx: open /etc/nginx/sites-enabled/example.conf: permission denied"
	var output bytes.Buffer
	writeWarnings(&output, discovery.Result{Warnings: []string{technical}})

	if strings.Contains(output.String(), technical) ||
		strings.Contains(output.String(), "/etc/nginx") ||
		strings.Contains(output.String(), "permission denied") {
		t.Fatalf("warning output exposed technical details: %s", output.String())
	}
	if !strings.Contains(output.String(), "Could not access some web server configuration files.") {
		t.Fatalf("warning output did not contain friendly message: %s", output.String())
	}
}

func TestWriteWarningsRetainsNoWarningMessage(t *testing.T) {
	var output bytes.Buffer
	writeWarnings(&output, discovery.Result{})
	if !strings.Contains(output.String(), "No warnings. Everything completed without reported issues.") {
		t.Fatalf("no-warning message missing: %s", output.String())
	}
}

func TestWriteDomainsReportsMissingCertificatePaths(t *testing.T) {
	var output bytes.Buffer
	writeDomains(&output, discovery.Result{
		Domains: []discovery.DomainResult{{
			Domain: inspectors.Domain{Name: "example.com"},
		}},
	})

	normalizedOutput := strings.Join(strings.Fields(output.String()), " ")
	for _, field := range []string{
		"SSL certificate : Not reported",
	} {
		if !strings.Contains(normalizedOutput, field) {
			t.Errorf("website report does not contain %q", field)
		}
	}
}

func TestDomainJSONKeepsPortsAsArrayAndDNSData(t *testing.T) {
	result := discovery.DomainResult{
		Domain: inspectors.Domain{
			Name:  "www.example.com",
			Ports: []int{80, 443},
		},
		DNS: dns.Result{
			ResolvedIPs:   []string{"192.0.2.10"},
			MatchesServer: true,
			Status:        "matches_server",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	var ports []int
	if err := json.Unmarshal(decoded["ports"], &ports); err != nil {
		t.Fatalf("ports JSON is not an integer array: %s (%v)", decoded["ports"], err)
	}
	if !reflect.DeepEqual(ports, []int{80, 443}) {
		t.Errorf("JSON ports = %#v, want [80 443]", ports)
	}
	if _, ok := decoded["dns"]; !ok {
		t.Fatal("JSON result is missing DNS verification data")
	}
}

func TestAppendJSONResultPreservesPriorScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-results.jsonl")

	first := map[string]string{"scan": "first"}
	second := map[string]string{"scan": "second"}

	for _, result := range []any{first, second} {
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if err := appendJSONResult(path, data); err != nil {
			t.Fatalf("appendJSONResult() error = %v", err)
		}
	}

	results := readjsonRecords(t, path)

	if len(results) != 2 || results[0]["scan"] != "first" || results[1]["scan"] != "second" {
		t.Errorf("stored results = %#v, want both scans in order", results)
	}
}

func TestAppendJSONResultDoesNotOverwriteInvalidExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-results.jsonl")
	original := []byte("{invalid")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	err := appendJSONResult(path, []byte(`{"scan":"new"}`))
	if err == nil {
		t.Fatal("appendJSONResult() error = nil, want invalid-file error")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("os.ReadFile() error = %v", readErr)
	}
	if !bytes.Equal(data, original) {
		t.Errorf("existing file changed to %q, want %q", data, original)
	}
}

func TestSaveScanResultSeparatesScanAndWarningEvents(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "scan-results.jsonl")
	errorsPath := filepath.Join(dir, "scan-errors.jsonl")
	originalResultsPath := ScanResultsFile
	originalErrorsPath := ScanErrorsFile
	ScanResultsFile = resultsPath
	ScanErrorsFile = errorsPath
	t.Cleanup(func() {
		ScanResultsFile = originalResultsPath
		ScanErrorsFile = originalErrorsPath
	})

	scannedAt := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	result := discovery.Result{
		Status:    "completed_with_warnings",
		ScannedAt: scannedAt,
		Warnings:  []string{"nginx: open /etc/nginx/example.conf: permission denied; token=secret-value"},
		ErrorEvents: []discovery.ScanError{discovery.NewScanError(
			"warning",
			"nginx",
			fmt.Errorf("open /etc/nginx/example.conf: permission denied; token=secret-value"),
			scannedAt.Add(time.Second),
		)},
	}
	if err := saveScanResult(result); err != nil {
		t.Fatalf("saveScanResult() error = %v", err)
	}

	results := readjsonRecords(t, resultsPath)
	if len(results) != 1 {
		t.Fatalf("got %d scan records, want one", len(results))
	}
	if results[0]["type"] != "scan_result" || results[0]["status"] != "completed_with_warnings" {
		t.Errorf("scan record = %#v", results[0])
	}
	if results[0]["scanned_at"] != scannedAt.Format(time.RFC3339Nano) {
		t.Errorf("scan timestamp = %#v, want %s", results[0]["scanned_at"], scannedAt.Format(time.RFC3339Nano))
	}
	for _, field := range []string{"warnings", "error_events"} {
		if _, ok := results[0][field]; ok {
			t.Errorf("scan record unexpectedly contains %q: %#v", field, results[0])
		}
	}

	events := readjsonRecords(t, errorsPath)
	if len(events) != 1 || events[0]["type"] != "warning" ||
		events[0]["code"] != "NGINX_CONFIG_ACCESS_FAILED" ||
		events[0]["message"] != "Could not access some web server configuration files." {
		t.Fatalf("warning events = %#v", events)
	}
	if events[0]["details"] != "open /etc/nginx/example.conf: permission denied; token=[REDACTED]" {
		t.Errorf("warning details = %#v, want redacted technical error", events[0]["details"])
	}
	if strings.Contains(events[0]["details"].(string), "secret-value") {
		t.Error("warning details exposed a secret")
	}
}

func TestSaveScanResultAppendsMultipleSuccessfulScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-results.jsonl")
	originalPath := ScanResultsFile
	ScanResultsFile = path
	t.Cleanup(func() { ScanResultsFile = originalPath })

	for _, status := range []string{"completed", "completed_with_warnings"} {
		if err := saveScanResult(discovery.Result{Status: status}); err != nil {
			t.Fatalf("saveScanResult(%q) error = %v", status, err)
		}
	}

	records := readjsonRecords(t, path)
	if len(records) != 2 ||
		records[0]["type"] != "scan_result" ||
		records[0]["status"] != "completed" ||
		records[1]["type"] != "scan_result" ||
		records[1]["status"] != "completed_with_warnings" {
		t.Fatalf("successful scan records = %#v", records)
	}
}

func TestWriteErrorLogsStructuredErrorWithoutExposingDetails(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "scan-results.jsonl")
	errorsPath := filepath.Join(dir, "scan-errors.jsonl")
	originalResultsPath := ScanResultsFile
	originalErrorsPath := ScanErrorsFile
	ScanResultsFile = resultsPath
	ScanErrorsFile = errorsPath
	t.Cleanup(func() {
		ScanResultsFile = originalResultsPath
		ScanErrorsFile = originalErrorsPath
	})

	const technical = "nginx: open /etc/nginx/sites-enabled/example.conf: permission denied"
	var output bytes.Buffer
	if err := WriteError(&output, "command_failed", fmt.Errorf("%s", technical), false); err != nil {
		t.Fatalf("WriteError() error = %v", err)
	}
	if strings.Contains(output.String(), technical) ||
		strings.Contains(output.String(), "/etc/nginx") ||
		strings.Contains(output.String(), "permission denied") {
		t.Fatalf("terminal error exposed technical details: %s", output.String())
	}

	records := readjsonRecords(t, errorsPath)
	if len(records) != 1 || records[0]["type"] != "error" {
		t.Fatalf("error records = %#v, want one error event", records)
	}
	if records[0]["details"] != technical {
		t.Errorf("logged details = %#v, want %q", records[0]["details"], technical)
	}
	if _, err := os.Stat(resultsPath); !os.IsNotExist(err) {
		t.Errorf("WriteError() created or accessed scan results file: %v", err)
	}
}

func TestSaveFailedScanResultAppendsFailureRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-results.jsonl")
	timestamp := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if err := SaveFailedScanResultTo(path, timestamp); err != nil {
		t.Fatalf("SaveFailedScanResultTo() error = %v", err)
	}

	records := readjsonRecords(t, path)
	if len(records) != 1 || records[0]["type"] != "scan_result" || records[0]["status"] != "failed" {
		t.Fatalf("failed scan record = %#v", records)
	}
}

func TestFailedScanLogsOneErrorEvent(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "scan-results.jsonl")
	errorsPath := filepath.Join(dir, "scan-errors.jsonl")
	originalResultsPath := ScanResultsFile
	originalErrorsPath := ScanErrorsFile
	ScanResultsFile = resultsPath
	ScanErrorsFile = errorsPath
	t.Cleanup(func() {
		ScanResultsFile = originalResultsPath
		ScanErrorsFile = originalErrorsPath
	})

	if err := SaveFailedScanResult(time.Now()); err != nil {
		t.Fatalf("SaveFailedScanResult() error = %v", err)
	}
	var output bytes.Buffer
	if err := WriteError(&output, "command_failed", fmt.Errorf("network unreachable"), false); err != nil {
		t.Fatalf("WriteError() error = %v", err)
	}

	results := readjsonRecords(t, resultsPath)
	events := readjsonRecords(t, errorsPath)
	if len(results) != 1 || results[0]["status"] != "failed" {
		t.Fatalf("failed scan records = %#v; want one failed scan", results)
	}
	if len(events) != 1 || events[0]["type"] != "error" {
		t.Fatalf("error events = %#v; want one error event", events)
	}
}

func TestWriteErrorJSONModeRemainsMachineReadable(t *testing.T) {
	dir := t.TempDir()
	originalResultsPath := ScanResultsFile
	originalErrorsPath := ScanErrorsFile
	ScanResultsFile = filepath.Join(dir, "scan-results.jsonl")
	ScanErrorsFile = filepath.Join(dir, "scan-errors.jsonl")
	t.Cleanup(func() {
		ScanResultsFile = originalResultsPath
		ScanErrorsFile = originalErrorsPath
	})

	var output bytes.Buffer
	if err := WriteError(&output, "command_failed", fmt.Errorf("lookup example.com: i/o timeout"), true); err != nil {
		t.Fatalf("WriteError() error = %v", err)
	}
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatalf("JSON error output is invalid: %v", err)
	}
	if payload.Error.Code != "command_failed" ||
		payload.Error.Message != "Could not verify the website's domain address." {
		t.Errorf("JSON error = %#v", payload.Error)
	}
}

func TestWriteErrorSurfacesjsonFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-file")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	originalResultsPath := ScanResultsFile
	originalErrorsPath := ScanErrorsFile
	ScanResultsFile = filepath.Join(t.TempDir(), "scan-results.jsonl")
	ScanErrorsFile = path
	t.Cleanup(func() {
		ScanResultsFile = originalResultsPath
		ScanErrorsFile = originalErrorsPath
	})

	var output bytes.Buffer
	err := WriteError(&output, "command_failed", fmt.Errorf("unexpected failure"), false)
	if err == nil {
		t.Fatal("WriteError() error = nil, want json write failure")
	}
	if !strings.Contains(output.String(), "Some checks could not be completed.") {
		t.Errorf("friendly error not displayed before logging failure: %s", output.String())
	}
}

func readjsonRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("json file has no final newline: %q", data)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	records := make([]map[string]any, 0, len(lines))
	for lineNumber, line := range lines {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("json line %d is invalid: %v", lineNumber+1, err)
		}
		records = append(records, record)
	}
	return records
}
