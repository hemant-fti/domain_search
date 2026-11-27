package validate_test

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"domain-search/pkg/models"
	"domain-search/pkg/ssl/internal/certtest"
	"domain-search/pkg/ssl/validate"
)

func TestCheckExpiry(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	tests := []struct {
		name       string
		notBefore  time.Time
		notAfter   time.Time
		wantStatus string
		wantDays   int
	}{
		{"valid", now.Add(-day), now.Add(90 * day), models.ExpiryStatusValid, 90},
		{"expiring at window", now.Add(-day), now.Add(30 * day), models.ExpiryStatusExpiring, 30},
		{"expiring soon", now.Add(-day), now.Add(5*day + time.Hour), models.ExpiryStatusExpiring, 5},
		{"expired", now.Add(-90 * day), now.Add(-3 * day), models.ExpiryStatusExpired, -3},
		{"expires exactly now", now.Add(-day), now, models.ExpiryStatusExpired, 0},
		{"not yet valid", now.Add(day), now.Add(90 * day), models.ExpiryStatusNotYetValid, 90},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{NotBefore: tt.notBefore, NotAfter: tt.notAfter}
			got := validate.CheckExpiry(cert, now, validate.DefaultRenewalWindow)
			if got.Status != tt.wantStatus || got.DaysRemaining != tt.wantDays {
				t.Errorf("CheckExpiry = %+v, want %s/%d", got, tt.wantStatus, tt.wantDays)
			}
		})
	}
}

func TestHostname(t *testing.T) {
	cert := certtest.New(t, certtest.Options{DNSNames: []string{"example.com", "*.example.org"}}).Cert

	tests := []struct {
		host string
		ok   bool
	}{
		{"example.com", true},
		{"www.example.org", true},
		{"example.org", false},
		{"other.com", false},
	}
	for _, tt := range tests {
		if err := validate.Hostname(cert, tt.host); (err == nil) != tt.ok {
			t.Errorf("Hostname(%q) error = %v, want ok=%v", tt.host, err, tt.ok)
		}
	}
}

func TestChain(t *testing.T) {
	root := certtest.New(t, certtest.Options{CommonName: "root", IsCA: true})
	inter := certtest.New(t, certtest.Options{CommonName: "intermediate", IsCA: true, Parent: root})
	leaf := certtest.New(t, certtest.Options{CommonName: "leaf", DNSNames: []string{"example.com"}, Parent: inter})

	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)

	t.Run("complete", func(t *testing.T) {
		chains, err := validate.Chain(leaf.Cert, []*x509.Certificate{inter.Cert},
			validate.ChainOptions{Roots: roots, DNSName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 1 || len(chains[0]) != 3 {
			t.Fatalf("chains = %v", chains)
		}
	})

	t.Run("missing intermediate", func(t *testing.T) {
		_, err := validate.Chain(leaf.Cert, nil, validate.ChainOptions{Roots: roots})
		if !errors.Is(err, validate.ErrMissingIntermediate) {
			t.Fatalf("error = %v, want ErrMissingIntermediate", err)
		}
	})

	t.Run("wrong hostname", func(t *testing.T) {
		_, err := validate.Chain(leaf.Cert, []*x509.Certificate{inter.Cert},
			validate.ChainOptions{Roots: roots, DNSName: "other.com"})
		if err == nil || errors.Is(err, validate.ErrMissingIntermediate) {
			t.Fatalf("error = %v, want hostname failure", err)
		}
	})

	t.Run("expired leaf", func(t *testing.T) {
		_, err := validate.Chain(leaf.Cert, []*x509.Certificate{inter.Cert},
			validate.ChainOptions{Roots: roots, At: time.Now().Add(10 * 365 * 24 * time.Hour)})
		if err == nil {
			t.Fatal("expected expiry failure")
		}
	})
}

func TestKeyPair(t *testing.T) {
	a := certtest.New(t, certtest.Options{CommonName: "a"})
	b := certtest.New(t, certtest.Options{CommonName: "b"})

	if err := validate.KeyPair(a.PEM(), a.KeyPEM(t)); err != nil {
		t.Errorf("matching pair: %v", err)
	}
	if err := validate.KeyPair(a.PEM(), b.KeyPEM(t)); err == nil {
		t.Error("mismatched pair accepted")
	}
}

func TestReport(t *testing.T) {
	now := time.Now()
	cert := certtest.New(t, certtest.Options{CommonName: "r", NotAfter: now.Add(10 * 24 * time.Hour)}).Cert
	got := validate.Report(cert, now)
	if !got.Installed || got.CommonName != "r" || got.ExpiryStatus != models.ExpiryStatusExpiring {
		t.Errorf("Report = %+v", got)
	}
	// NotAfter is truncated to whole seconds, so allow either side of 10 days.
	if got.DaysRemaining != 9 && got.DaysRemaining != 10 {
		t.Errorf("DaysRemaining = %d, want about 10", got.DaysRemaining)
	}
}
