package nginx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"domain-search/pkg/models"
)

func writeTestCert(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCertificates(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	writeTestCert(t, certPath, time.Now().Add(60*24*time.Hour))
	missing := filepath.Join(dir, "missing.pem")

	domains := []models.Domain{
		{Name: "example.com", Ports: []int{80, 443}, SSLCertificate: certPath},
		{Name: "www.example.com", Ports: []int{8443}, SSLCertificate: `"` + certPath + `"`},
		{Name: "broken.example.com", SSLCertificate: missing},
		{Name: "dynamic.example.com", SSLCertificate: "/etc/ssl/$ssl_server_name.pem"},
		{Name: "plain.example.com"},
	}

	err := LoadCertificates(domains, time.Now())
	if err == nil || !strings.Contains(err.Error(), "missing.pem") {
		t.Fatalf("error = %v, want the missing file reported", err)
	}

	first := domains[0].Certificates
	if len(first) != 1 || !first[0].Installed || first[0].CommonName != "example.com" {
		t.Fatalf("example.com certificates = %+v", first)
	}
	if first[0].Port != 443 || first[0].FQDN != "example.com" || *first[0].Paths.Fullchain != certPath {
		t.Errorf("endpoint fields = %+v", first[0])
	}
	if first[0].ExpiryStatus != models.ExpiryStatusValid {
		t.Errorf("ExpiryStatus = %q", first[0].ExpiryStatus)
	}

	second := domains[1].Certificates
	if len(second) != 1 || second[0].FingerprintSHA256 != first[0].FingerprintSHA256 || second[0].Port != 0 {
		t.Errorf("shared file should give the same certificate: %+v", second)
	}

	broken := domains[2].Certificates
	if len(broken) != 1 || broken[0].Installed || broken[0].Error == "" {
		t.Errorf("broken certificate = %+v", broken)
	}

	if len(domains[3].Certificates) != 0 || len(domains[4].Certificates) != 0 {
		t.Error("variable paths and domains without ssl_certificate must be skipped")
	}
}
