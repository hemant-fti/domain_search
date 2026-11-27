package render

import (
	"strings"
	"testing"

	"domain-search/pkg/models"
)

func TestWriteHumanShowsWarningsCertificatesAndDNS(t *testing.T) {
	path := "/etc/ssl/site.pem"
	res := models.Result{
		Status: "completed",
		Server: models.Info{Hostname: "web1", PrimaryIP: "192.0.2.1"},
		Domains: []models.DomainResult{{
			Domain: models.Domain{
				Name:   "example.com",
				Source: "nginx",
				Ports:  []int{443},
				Certificates: []models.CertificateResult{
					{Installed: true, CommonName: "example.com", ExpiryStatus: models.ExpiryStatusExpiring, DaysRemaining: 7, Paths: models.CertificatePaths{Fullchain: &path}},
					{Installed: false, Error: "no certificate is bound"},
				},
			},
			DNS: models.DNSResult{Status: models.DNSStatusMatchesServer, MatchesServer: true},
		}},
		Warnings:    []string{"nginx scan: open /secret: permission denied"},
		ErrorEvents: []models.ScanError{{Message: "Could not access some web server configuration files."}},
	}

	var out strings.Builder
	if err := WriteHuman(&out, res); err != nil {
		t.Fatal(err)
	}
	text := out.String()

	for _, want := range []string{
		"192.0.2.1",
		"Could not access some web server configuration files.",
		"Expiring soon (7 days left)",
		"/etc/ssl/site.pem",
		"no certificate is bound",
		"matches",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if strings.Contains(text, "/secret") {
		t.Error("raw warning text leaked into the report; only friendly messages should be shown")
	}
}

func TestWriteDomainsEmpty(t *testing.T) {
	var out strings.Builder
	if err := WriteDomains(&out, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Server Discovery Report") {
		t.Errorf("unexpected output: %q", out.String())
	}
}
