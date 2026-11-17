package nginx

import (
	"reflect"
	"testing"
)

func TestParseCollectsAliasesPathsRootsAndPorts(t *testing.T) {
	config := `# configuration file /etc/nginx/sites-enabled/demo:
server {
    listen 80;
    listen 443 ssl;
    server_name demo.local www.demo.local *.demo.local;
    root /var/www/demo;
}
`

	domains := Parse(config)
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	domain := domains[0]
	if domain.Name != "demo.local" {
		t.Errorf("domain = %q, want demo.local", domain.Name)
	}
	if !reflect.DeepEqual(domain.Aliases, []string{"www.demo.local", "*.demo.local"}) {
		t.Errorf("aliases = %#v", domain.Aliases)
	}
	if domain.ConfigPath != "/etc/nginx/sites-enabled/demo" {
		t.Errorf("config path = %q", domain.ConfigPath)
	}
	if domain.DocumentRoot != "/var/www/demo" {
		t.Errorf("document root = %q", domain.DocumentRoot)
	}
	if !reflect.DeepEqual(domain.Ports, []int{80, 443}) {
		t.Errorf("ports = %#v", domain.Ports)
	}
}

func TestParseCollectsSSLCertificatePathsAndSortedUniquePorts(t *testing.T) {
	config := `server {
    listen 8443 ssl;
    listen 80;
    listen 80;
    server_name www.example.com;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
`

	domains := Parse(config)
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}

	domain := domains[0]
	if domain.SSLCertificate != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Errorf("SSL certificate = %q", domain.SSLCertificate)
	}

	if !domain.SSL {
		t.Error("SSL = false, want true for a custom SSL port")
	}
	if !reflect.DeepEqual(domain.Ports, []int{80, 8443}) {
		t.Errorf("ports = %#v, want [80 8443]", domain.Ports)
	}
}

func TestParseHandlesMissingSSLCertificateDirectives(t *testing.T) {
	domains := Parse(`server {
    listen 8080;
    server_name example.com;
}
`)

	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	if domains[0].SSLCertificate != "" {
		t.Errorf("SSL certificate = %q, want empty string", domains[0].SSLCertificate)
	}
}
