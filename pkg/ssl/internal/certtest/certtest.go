// Package certtest generates throwaway certificates for tests.
package certtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// KeyType selects the generated key algorithm.
type KeyType int

const (
	ECDSA KeyType = iota
	RSA
	Ed25519
)

// Options describes a certificate to generate.
type Options struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	NotBefore  time.Time
	NotAfter   time.Time
	Key        KeyType
	IsCA       bool
	Parent     *Issued // nil means self-signed
}

// Issued is a generated certificate and its private key.
type Issued struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// PEM returns the certificate as PEM.
func (i *Issued) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Cert.Raw})
}

// KeyPEM returns the private key as PKCS#8 PEM.
func (i *Issued) KeyPEM(t testing.TB) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(i.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

var serial int64 = 1000

// New generates a certificate.
func New(t testing.TB, o Options) *Issued {
	t.Helper()
	key := newKey(t, o.Key)

	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: o.CommonName, Organization: []string{"hostscope test"}},
		DNSNames:              o.DNSNames,
		IPAddresses:           o.IPs,
		NotBefore:             o.NotBefore,
		NotAfter:              o.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  o.IsCA,
	}
	if o.IsCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.ExtKeyUsage = nil
	}

	parentCert, parentKey := tmpl, key
	if o.Parent != nil {
		parentCert, parentKey = o.Parent.Cert, o.Parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Issued{Cert: cert, Key: key}
}

func newKey(t testing.TB, kt KeyType) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch kt {
	case RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}
