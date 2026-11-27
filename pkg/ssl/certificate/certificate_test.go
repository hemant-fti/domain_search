package certificate_test

import (
	"crypto/sha1" //nolint:gosec // test compares thumbprints
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"domain-search/pkg/ssl/certificate"
	"domain-search/pkg/ssl/internal/certtest"
)

func TestDescribe(t *testing.T) {
	tests := []struct {
		name     string
		key      certtest.KeyType
		wantType string
		wantBits int
		wantSig  string
	}{
		{"ecdsa", certtest.ECDSA, "ECDSA", 256, "ECDSA-SHA256"},
		{"rsa", certtest.RSA, "RSA", 2048, "RSA-SHA256"},
		{"ed25519", certtest.Ed25519, "Ed25519", 256, "Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notAfter := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			issued := certtest.New(t, certtest.Options{
				CommonName: "example.com",
				DNSNames:   []string{"example.com", "www.example.com"},
				IPs:        []net.IP{net.ParseIP("192.0.2.10")},
				NotAfter:   notAfter,
				Key:        tt.key,
			})
			got := certificate.Describe(issued.Cert)

			if !got.Installed || got.CommonName != "example.com" {
				t.Errorf("Installed=%v CommonName=%q", got.Installed, got.CommonName)
			}
			if got.KeyType != tt.wantType || got.KeyBits != tt.wantBits {
				t.Errorf("key = %s/%d, want %s/%d", got.KeyType, got.KeyBits, tt.wantType, tt.wantBits)
			}
			if got.SigAlg != tt.wantSig {
				t.Errorf("SigAlg = %q, want %q", got.SigAlg, tt.wantSig)
			}
			if got.NotAfter != "2030-01-02T03:04:05+00:00" {
				t.Errorf("NotAfter = %q", got.NotAfter)
			}
			wantSANs := []string{"example.com", "www.example.com", "192.0.2.10"}
			if !slices.Equal(got.SANs, wantSANs) {
				t.Errorf("SANs = %v, want %v", got.SANs, wantSANs)
			}

			sum256 := sha256.Sum256(issued.Cert.Raw)
			if got.FingerprintSHA256 != strings.ToUpper(hex.EncodeToString(sum256[:])) {
				t.Errorf("FingerprintSHA256 = %q", got.FingerprintSHA256)
			}
			sum1 := sha1.Sum(issued.Cert.Raw) //nolint:gosec
			if got.FingerprintSHA1 != strings.ToUpper(hex.EncodeToString(sum1[:])) {
				t.Errorf("FingerprintSHA1 = %q", got.FingerprintSHA1)
			}
			spki := sha256.Sum256(issued.Cert.RawSubjectPublicKeyInfo)
			if got.SPKISHA256 != hex.EncodeToString(spki[:]) {
				t.Errorf("SPKISHA256 = %q", got.SPKISHA256)
			}
			if !slices.Contains(got.KeyUsage, "digital_signature") || !slices.Equal(got.ExtKeyUsage, []string{"server_auth"}) {
				t.Errorf("usage = %v / %v", got.KeyUsage, got.ExtKeyUsage)
			}
		})
	}
}

func TestParsePEMReturnsChainInOrder(t *testing.T) {
	ca := certtest.New(t, certtest.Options{CommonName: "ca", IsCA: true})
	leaf := certtest.New(t, certtest.Options{CommonName: "leaf", Parent: ca})

	data := append(append([]byte("junk before\n"), leaf.PEM()...), ca.PEM()...)
	certs, err := certificate.ParsePEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !certs[0].Equal(leaf.Cert) || !certs[1].Equal(ca.Cert) {
		t.Fatalf("ParsePEM returned %d certs in wrong order", len(certs))
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := certificate.ParsePEM([]byte("no pem here")); !errors.Is(err, certificate.ErrNoCertificate) {
		t.Errorf("ParsePEM(no pem) error = %v", err)
	}
	if _, err := certificate.ParseDER(nil); !errors.Is(err, certificate.ErrNoCertificate) {
		t.Errorf("ParseDER(nil) error = %v", err)
	}
	if _, err := certificate.ParseDER([]byte{1, 2, 3}); err == nil {
		t.Error("ParseDER(garbage) succeeded")
	}
}

func TestLoadFile(t *testing.T) {
	issued := certtest.New(t, certtest.Options{CommonName: "file.example"})
	dir := t.TempDir()

	pemPath := filepath.Join(dir, "cert.pem")
	derPath := filepath.Join(dir, "cert.der")
	badPath := filepath.Join(dir, "bad.pem")
	writeFile(t, pemPath, issued.PEM())
	writeFile(t, derPath, issued.Cert.Raw)
	writeFile(t, badPath, []byte("not a certificate"))

	for _, path := range []string{pemPath, derPath} {
		certs, err := certificate.LoadFile(path)
		if err != nil || len(certs) != 1 || !certs[0].Equal(issued.Cert) {
			t.Errorf("LoadFile(%s) = %d certs, %v", filepath.Base(path), len(certs), err)
		}
	}
	if _, err := certificate.LoadFile(badPath); !errors.Is(err, certificate.ErrNoCertificate) {
		t.Errorf("LoadFile(bad) error = %v", err)
	}
	if _, err := certificate.LoadFile(filepath.Join(dir, "missing.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadFile(missing) error = %v", err)
	}
}

func TestNormalizeThumbprint(t *testing.T) {
	tests := map[string]string{
		"ab cd ef":       "ABCDEF",
		" aa:bb:cc ":     "AABBCC",
		"0123456789ABCD": "0123456789ABCD",
		"":               "",
	}
	for in, want := range tests {
		if got := certificate.NormalizeThumbprint(in); got != want {
			t.Errorf("NormalizeThumbprint(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
