// Package certificate parses X.509 certificates and describes their metadata.
//
// It is a thin layer over crypto/x509: it never implements cryptography itself.
// It has no knowledge of web servers, IIS, or certificate stores.
package certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 thumbprints are how Windows identifies certificates.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"domain-search/pkg/models"
)

// ErrNoCertificate is returned when input contains no certificate.
var ErrNoCertificate = errors.New("no certificate found")

// ParseDER parses one DER-encoded certificate. The input is copied, so the
// caller may reuse or free its buffer afterwards.
func ParseDER(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 {
		return nil, ErrNoCertificate
	}
	cert, err := x509.ParseCertificate(append([]byte(nil), der...))
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ParsePEM parses every CERTIFICATE block in data, in order. The first
// certificate is normally the leaf and the rest its chain.
func ParsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificate
	}
	return certs, nil
}

// LoadFile reads a PEM or DER certificate file and returns its certificates.
func LoadFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}
	certs, err := ParsePEM(data)
	if err == nil {
		return certs, nil
	}
	if !errors.Is(err, ErrNoCertificate) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cert, derErr := ParseDER(data)
	if derErr != nil {
		return nil, fmt.Errorf("%s: %w", path, ErrNoCertificate)
	}
	return []*x509.Certificate{cert}, nil
}

// Describe returns the certificate's metadata as a CertificateResult with
// Installed=true. Endpoint fields (IP, FQDN, Port, Paths) and expiry status
// are left for the caller to fill in.
func Describe(cert *x509.Certificate) models.CertificateResult {
	result := models.CertificateResult{
		Installed:    true,
		CommonName:   cert.Subject.CommonName,
		IssuerDN:     cert.Issuer.String(),
		SubjectDN:    cert.Subject.String(),
		NotBefore:    FormatTime(cert.NotBefore),
		NotAfter:     FormatTime(cert.NotAfter),
		SerialHex:    strings.ToUpper(cert.SerialNumber.Text(16)),
		SerialNumber: cert.SerialNumber.String(),
		SigAlg:       SignatureAlgorithmName(cert.SignatureAlgorithm),
		SANs:         SANs(cert),
		KeyUsage:     KeyUsages(cert.KeyUsage),
		ExtKeyUsage:  ExtKeyUsages(cert.ExtKeyUsage),
	}
	result.KeyType, result.KeyBits = KeyTypeAndBits(cert)

	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	result.SPKISHA256 = hex.EncodeToString(spki[:]) // lowercase by convention
	result.FingerprintSHA256 = FingerprintSHA256(cert)
	result.FingerprintSHA1 = Thumbprint(cert)
	return result
}

// FingerprintSHA256 returns the upper-case hex SHA-256 of the DER certificate.
func FingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Thumbprint returns the upper-case hex SHA-1 of the DER certificate, which is
// the identifier Windows and IIS use.
func Thumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw) //nolint:gosec // identifier, not a security decision
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// NormalizeThumbprint upper-cases a thumbprint and strips spaces and colons.
func NormalizeThumbprint(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, ":", "")
	return strings.ToUpper(value)
}

// SANs returns the DNS names and IP addresses in the certificate's subject
// alternative names. It never returns nil.
func SANs(cert *x509.Certificate) []string {
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return sans
}

// KeyTypeAndBits returns the public key algorithm name and its size in bits.
func KeyTypeAndBits(cert *x509.Certificate) (string, int) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// SignatureAlgorithmName returns a short name such as "RSA-SHA256".
func SignatureAlgorithmName(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.ECDSAWithSHA256:
		return "ECDSA-SHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSA-SHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSA-SHA512"
	case x509.SHA256WithRSA:
		return "RSA-SHA256"
	case x509.SHA384WithRSA:
		return "RSA-SHA384"
	case x509.SHA512WithRSA:
		return "RSA-SHA512"
	case x509.SHA1WithRSA:
		return "RSA-SHA1"
	default:
		return a.String()
	}
}

// FormatTime prints a time as 2006-01-02T15:04:05+00:00 in UTC.
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05+00:00")
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digital_signature"},
	{x509.KeyUsageContentCommitment, "content_commitment"},
	{x509.KeyUsageKeyEncipherment, "key_encipherment"},
	{x509.KeyUsageDataEncipherment, "data_encipherment"},
	{x509.KeyUsageKeyAgreement, "key_agreement"},
	{x509.KeyUsageCertSign, "cert_sign"},
	{x509.KeyUsageCRLSign, "crl_sign"},
	{x509.KeyUsageEncipherOnly, "encipher_only"},
	{x509.KeyUsageDecipherOnly, "decipher_only"},
}

// KeyUsages returns the names of the key usage bits that are set.
func KeyUsages(usage x509.KeyUsage) []string {
	var names []string
	for _, ku := range keyUsageNames {
		if usage&ku.bit != 0 {
			names = append(names, ku.name)
		}
	}
	return names
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "any",
	x509.ExtKeyUsageServerAuth:      "server_auth",
	x509.ExtKeyUsageClientAuth:      "client_auth",
	x509.ExtKeyUsageCodeSigning:     "code_signing",
	x509.ExtKeyUsageEmailProtection: "email_protection",
	x509.ExtKeyUsageTimeStamping:    "time_stamping",
	x509.ExtKeyUsageOCSPSigning:     "ocsp_signing",
}

// ExtKeyUsages returns the names of the extended key usages.
func ExtKeyUsages(usages []x509.ExtKeyUsage) []string {
	var names []string
	for _, u := range usages {
		name, ok := extKeyUsageNames[u]
		if !ok {
			name = fmt.Sprintf("unknown(%d)", u)
		}
		names = append(names, name)
	}
	return names
}
