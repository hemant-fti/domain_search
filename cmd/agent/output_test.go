package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"domain-scout/service/discovery"
	"domain-scout/service/dns"
	"domain-scout/service/inspectors"
	"domain-scout/service/server"
)

func TestWriteHumanIncludesDiscoveryFields(t *testing.T) {
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
				Name:         "example.com",
				Source:       "nginx",
				ConfigPath:   "/etc/nginx/sites-enabled/example",
				DocumentRoot: "/var/www/example",
				ProxyTarget:  "http://127.0.0.1:8080",
				SSL:          true,
				Aliases:      []string{"www.example.com"},
				Ports:        []int{80, 443},
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
	if err := writeHuman(&output, result); err != nil {
		t.Fatalf("writeHuman() error = %v", err)
	}

	for _, field := range []string{
		"Scan status: completed",
		"Main IP address: 192.0.2.10",
		"nginx: running",
		"Listening ports: 80, 443",
		"Time since startup: 1 day, 1 hour, 1 minute, 1 second",
		"Root disk space: 100.00 GiB total, 60.00 GiB used, 40.00 GiB free",
		"Websites found: 1",
		"Forwards requests to: http://127.0.0.1:8080",
		"Secure HTTPS configured: Yes",
		"DNS result: The website name points to this server",
		"DNS addresses: 192.0.2.10",
		"DNS points to this server: Yes",
		"Some metrics were unavailable",
	} {
		if !strings.Contains(output.String(), field) {
			t.Errorf("human-readable output does not contain %q", field)
		}
	}
}
