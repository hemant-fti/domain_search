//go:build windows

// Package iis returns the TLS certificate that is actually bound to
// every HTTPS binding configured in IIS, and can also fetch the certificate
// presented by a public endpoint (to detect CDN/proxy TLS termination).
//
// Usage:
//
//	certs, err := iis.GetIISCertificates()
//	cert, err := iis.GetPublicCertificate(ctx, "example.com", 443)
//
// How the IIS path works:
//
//  1. Read the HTTPS bindings (IP, port, hostname, sslFlags) from IIS's
//     applicationHost.config.
//  2. Ask HTTP.sys (the Windows kernel HTTP driver) which certificate thumbprint
//     is bound to each binding. HTTP.sys is the source of truth: the certificate
//     is NOT stored in applicationHost.config.
//  3. Find that thumbprint in the LocalMachine certificate store and extract
//     its details.
//
// Requirements: Windows, run as Administrator, Go 1.18+, and
// `go get golang.org/x/sys/windows`. A 32-bit binary on 64-bit Windows is
// handled through Sysnative.
//
// Limitation: Centralized Certificate Store (CCS) bindings select the
// certificate dynamically and are reported as unresolved with an explicit error.
package iis

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"domain-search/models"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// GetIISCertificates returns one result per HTTPS binding in IIS.
// Bindings whose certificate cannot be resolved are still returned with
// Installed=false. The first error encountered (if any) is returned alongside
// the results, so callers get partial data instead of nothing.
func GetIISCertificates() ([]models.CertificateResult, error) {
	bindings, readErr := ReadHTTPSBindingsFromIIS()
	if len(bindings) == 0 {
		// Nothing to look up: do not initialize HTTP.sys at all.
		return []models.CertificateResult{}, readErr
	}

	if err := startHTTPSys(); err != nil {
		return nil, err
	}
	defer stopHTTPSys()

	firstErr := readErr
	results := make([]models.CertificateResult, 0, len(bindings))

	for _, b := range bindings {
		cert, err := getCertForBinding(b)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("site %q, %s:%d (%q): %w", b.SiteName, b.IP, b.Port, b.FQDN, err)
			}
			results = append(results, toCertificateResult(b, nil)) // Installed=false
			continue
		}
		results = append(results, toCertificateResult(b, cert))
	}
	return results, firstErr
}

// GetPublicCertificate returns the certificate presented at host:port.
// Verification is intentionally off: this is inventory, not validation,
// so expired, self-signed, and mismatched certs must still be reported.
//
// Compare its SHA-256 fingerprint with the IIS (origin) certificate to detect
// whether a CDN/proxy such as Cloudflare terminates TLS in front of IIS.
func GetPublicCertificate(ctx context.Context, host string, port int) (*x509.Certificate, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("unexpected connection type")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificate presented")
	}
	return certs[0], nil
}

// -----------------------------------------------------------------------------
// Step 1: read HTTPS bindings from the IIS configuration
// -----------------------------------------------------------------------------

// iisConfig is the small part of applicationHost.config we care about:
//
//	<system.applicationHost><sites><site name="..."><bindings>
//	    <binding protocol="https" bindingInformation="*:443:example.com" sslFlags="1" />
type iisConfig struct {
	Sites []struct {
		Name     string `xml:"name,attr"`
		Bindings []struct {
			Protocol string `xml:"protocol,attr"`
			Info     string `xml:"bindingInformation,attr"` // "<ip>:<port>:<hostname>"
			SSLFlags string `xml:"sslFlags,attr"`
		} `xml:"bindings>binding"`
	} `xml:"system.applicationHost>sites>site"`
}

// IISBinding is one HTTPS binding of an IIS site.
type IISBinding struct {
	SiteName string
	IP       string // "*" means "all unassigned"
	Port     int
	FQDN     string // may be empty (binding without a hostname)
	SSLFlags uint32
}

// IIS sslFlags bits that affect certificate lookup.
const (
	sslFlagSNI = 1 // Server Name Indication
	sslFlagCCS = 2 // Centralized Certificate Store
)

// ReadHTTPSBindingsFromIIS reads applicationHost.config and returns its HTTPS
// bindings. A malformed binding does not stop the scan: valid bindings are
// still returned together with the first parse error.
func ReadHTTPSBindingsFromIIS() ([]IISBinding, error) {
	configPath, err := GetIISConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read IIS configuration: %w", err)
	}
	var config iisConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse IIS configuration: %w", err)
	}

	var bindings []IISBinding
	var firstErr error
	for _, site := range config.Sites {
		for _, b := range site.Bindings {
			// Only https bindings have a certificate (http, ftp, net.tcp do not).
			if !strings.EqualFold(b.Protocol, "https") {
				continue
			}
			ip, port, host, err := splitBindingInfo(b.Info)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("site %q, binding %q: %w", site.Name, b.Info, err)
				}
				continue
			}
			var flags uint64
			if b.SSLFlags != "" {
				flags, _ = strconv.ParseUint(strings.TrimSpace(b.SSLFlags), 10, 32) // bad value => 0, still scan it
			}
			bindings = append(bindings, IISBinding{
				SiteName: site.Name,
				IP:       ip,
				Port:     port,
				FQDN:     host,
				SSLFlags: uint32(flags),
			})
		}
	}
	return bindings, firstErr
}

// splitBindingInfo splits "<ip>:<port>:<host>".
// IPv6 addresses are wrapped in brackets, e.g. "[::1]:443:example.com".
func splitBindingInfo(info string) (ip string, port int, host string, err error) {
	invalid := errors.New("expected <ip>:<port>:<host>")

	var rest string
	if strings.HasPrefix(info, "[") {
		end := strings.Index(info, "]")
		if end < 0 || end+1 >= len(info) || info[end+1] != ':' {
			return "", 0, "", invalid
		}
		ip, rest = info[1:end], info[end+2:]
	} else {
		var ok bool
		ip, rest, ok = strings.Cut(info, ":")
		if !ok {
			return "", 0, "", invalid
		}
	}

	portText, host, ok := strings.Cut(rest, ":")
	if !ok {
		return "", 0, "", invalid
	}
	port, err = strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("invalid port %q", portText)
	}
	return ip, port, strings.TrimSpace(host), nil
}

// GetIISConfigPath returns the path of applicationHost.config, or an error if
// it cannot be found (IIS not installed, or no permission).
func GetIISConfigPath() (string, error) {
	windowsDir := os.Getenv("windir")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}

	build := func(systemDir string) string {
		return filepath.Join(windowsDir, systemDir, "inetsrv", "config", "applicationHost.config")
	}

	// A 32-bit process on 64-bit Windows is redirected away from System32.
	// Sysnative bypasses that, but does not exist on native 32-bit Windows.
	if runtime.GOARCH == "386" {
		if p := build("Sysnative"); fileExists(p) {
			return p, nil
		}
	}

	p := build("System32")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("IIS configuration unavailable at %s: %w", p, err)
	}
	return p, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// -----------------------------------------------------------------------------
// Step 2: ask HTTP.sys which certificate is bound to a binding
// -----------------------------------------------------------------------------

var (
	httpapi = windows.NewLazySystemDLL("httpapi.dll")

	procHTTPInitialize                = httpapi.NewProc("HttpInitialize")
	procHTTPTerminate                 = httpapi.NewProc("HttpTerminate")
	procHTTPQueryServiceConfiguration = httpapi.NewProc("HttpQueryServiceConfiguration")
)

const (
	// HTTPAPI_VERSION { Major: 2, Minor: 0 } is passed BY VALUE as one 32-bit
	// number: Major in the low 16 bits, Minor in the high 16 bits.
	httpAPIVersion2 = 2

	httpInitializeConfig = 0x2 // HTTP_INITIALIZE_CONFIG: needed to read configuration

	// HTTP_SERVICE_CONFIG_ID values.
	configIDSSLCert    = 1 // certificates bound to IP:port
	configIDSSLSNICert = 5 // certificates bound to hostname:port (SNI)

	queryExact = 0 // HttpServiceConfigQueryExact: look up one specific key

	afInet  = 2  // AF_INET
	afInet6 = 23 // AF_INET6

	// Upper bound for a buffer size requested by HTTP.sys. Real results are
	// well under 1 KB; this only protects against garbage values.
	maxHTTPBufferSize = 16 * 1024 * 1024
)

// sockaddrStorage mirrors the Windows SOCKADDR_STORAGE (128 bytes, 8-byte
// aligned). [16]uint64 gives the exact size AND the alignment.
type sockaddrStorage [16]uint64

// sslParam mirrors HTTP_SERVICE_CONFIG_SSL_PARAM.
// Pointer fields are uintptr because they point into Windows-owned memory
// (our output buffer), not Go memory; they are bounds-checked before use.
type sslParam struct {
	HashLength                    uint32
	Hash                          uintptr // certificate SHA-1 thumbprint
	AppID                         windows.GUID
	StoreName                     uintptr // UTF-16, e.g. "MY" or "WebHosting"
	DefaultCertCheckMode          uint32
	RevocationFreshnessTime       uint32
	RevocationURLRetrievalTimeout uint32
	SslCtlIdentifier              uintptr
	SslCtlStoreName               uintptr
	Flags                         uint32
}

// ipPortQuery is the input for an IP:port binding lookup.
type ipPortQuery struct {
	QueryDesc uint32
	IPPort    *sockaddrStorage
	Token     uint32
}

// ipPortResult is the output for an IP:port binding (HTTP_SERVICE_CONFIG_SSL_SET).
type ipPortResult struct {
	KeyIPPort uintptr
	Param     sslParam
}

// sniQuery is the input for a hostname:port (SNI) binding lookup.
type sniQuery struct {
	QueryDesc uint32
	IPPort    sockaddrStorage
	Host      *uint16
	Token     uint32
}

// sniResult is the output for a hostname:port (SNI) binding (HTTP_SERVICE_CONFIG_SSL_SNI_SET).
type sniResult struct {
	KeyIPPort sockaddrStorage
	KeyHost   uintptr
	Param     sslParam
}

// startHTTPSys initializes the HTTP Server API so we can read its configuration.
func startHTTPSys() error {
	if err := httpapi.Load(); err != nil {
		return fmt.Errorf("load httpapi.dll: %w", err)
	}
	r, _, _ := procHTTPInitialize.Call(httpAPIVersion2, httpInitializeConfig, 0)
	if rc := uint32(r); rc != 0 { // the Windows API returns a 32-bit code
		return fmt.Errorf("HttpInitialize: %w", windows.Errno(rc))
	}
	return nil
}

// stopHTTPSys releases the HTTP Server API.
func stopHTTPSys() {
	procHTTPTerminate.Call(httpInitializeConfig, 0)
}

// buildSockaddr builds the Windows socket address for a binding IP and port.
func buildSockaddr(ip string, port int) (*sockaddrStorage, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid binding IP %q: %w", ip, err)
	}
	addr = addr.Unmap()

	sa := new(sockaddrStorage)
	raw := (*[128]byte)(unsafe.Pointer(sa))

	// Layout: family (host order) | port (network order) | address ...
	binary.BigEndian.PutUint16(raw[2:4], uint16(port))
	if addr.Is4() {
		binary.LittleEndian.PutUint16(raw[0:2], afInet)
		ip4 := addr.As4()
		copy(raw[4:8], ip4[:]) // sockaddr_in: address at offset 4
	} else {
		binary.LittleEndian.PutUint16(raw[0:2], afInet6)
		ip6 := addr.As16()
		copy(raw[8:24], ip6[:]) // sockaddr_in6: address at offset 8 (after flowinfo)
	}
	return sa, nil
}

// ipsToTry lists the IPs to look up in HTTP.sys for an IIS binding IP.
//   - "All unassigned" bindings can be registered as 0.0.0.0 and/or [::].
//   - A specific IP falls back to the matching wildcard, because HTTP.sys
//     serves a wildcard-bound certificate for IPs without their own entry.
func ipsToTry(ip string) []string {
	if ip == "" || ip == "*" {
		return []string{"0.0.0.0", "::"}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.IsUnspecified() {
		return []string{ip}
	}
	if addr.Unmap().Is4() {
		return []string{ip, "0.0.0.0"}
	}
	return []string{ip, "::"}
}

// kernelBuffer is the output buffer filled in by HTTP.sys. HTTP.sys stores
// variable-length data (thumbprint, store name) INSIDE this same buffer and
// hands us pointers to it. []uint64 keeps it 8-byte aligned, and every
// pointer is bounds-checked before it is read.
type kernelBuffer []uint64

func (b kernelBuffer) bytes() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b)*8)
}

// offsetOf converts an address inside the buffer into a byte offset.
// Uses subtraction-based checks so addr+length can never overflow.
func (b kernelBuffer) offsetOf(addr, length uintptr) (int, error) {
	if len(b) == 0 {
		return 0, errors.New("empty HTTP.sys buffer")
	}
	base := uintptr(unsafe.Pointer(&b[0]))
	size := uintptr(len(b)) * 8
	if addr < base {
		return 0, errors.New("HTTP.sys returned a pointer outside its buffer")
	}
	offset := addr - base
	if offset > size || length > size-offset {
		return 0, errors.New("HTTP.sys returned a pointer outside its buffer")
	}
	return int(offset), nil
}

// readBytes copies n bytes found at addr (an address inside the buffer).
func (b kernelBuffer) readBytes(addr uintptr, n uint32) ([]byte, error) {
	off, err := b.offsetOf(addr, uintptr(n))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b.bytes()[off:off+int(n)]...), nil
}

// readUTF16 reads a NUL-terminated UTF-16 string found at addr.
func (b kernelBuffer) readUTF16(addr uintptr) (string, error) {
	off, err := b.offsetOf(addr, 2)
	if err != nil {
		return "", err
	}
	raw := b.bytes()[off:]
	var chars []uint16
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i:])
		if c == 0 {
			return windows.UTF16ToString(chars), nil
		}
		chars = append(chars, c)
	}
	return "", errors.New("unterminated string in HTTP.sys buffer")
}

// callHTTPSysQuery wraps HttpQueryServiceConfiguration. The API must be called
// once to learn the required buffer size, then again with a big enough buffer.
func callHTTPSysQuery(configID uintptr, input unsafe.Pointer, inputSize uintptr) (kernelBuffer, error) {
	var size uint32 // 0 on the first call = "tell me how much space you need"

	for attempt := 0; attempt < 3; attempt++ {
		var buf kernelBuffer
		var out unsafe.Pointer
		if size > 0 {
			if size > maxHTTPBufferSize {
				return nil, fmt.Errorf("invalid HTTP.sys buffer size: %d", size)
			}
			words := (uint64(size) + 7) / 8
			buf = make(kernelBuffer, int(words))
			out = unsafe.Pointer(&buf[0])
		}

		r, _, _ := procHTTPQueryServiceConfiguration.Call(
			0, // no service handle
			configID,
			uintptr(input),
			inputSize,
			uintptr(out),
			uintptr(len(buf)*8),
			uintptr(unsafe.Pointer(&size)),
			0, // no overlapped I/O
		)
		runtime.KeepAlive(buf)

		switch rc := uint32(r); rc {
		case 0:
			if len(buf) == 0 {
				return nil, errors.New("HTTP.sys returned an empty result")
			}
			return buf, nil
		case uint32(windows.ERROR_INSUFFICIENT_BUFFER):
			continue // size now holds the required length; retry
		default:
			return nil, windows.Errno(rc)
		}
	}
	return nil, errors.New("HTTP.sys buffer size kept changing")
}

// boundCert is what HTTP.sys tells us: which certificate, in which store.
type boundCert struct {
	Thumbprint []byte // SHA-1
	StoreName  string // under LocalMachine
}

// readBoundCert extracts the thumbprint and store name from an HTTP.sys result.
func readBoundCert(buf kernelBuffer, p *sslParam) (boundCert, error) {
	if p.HashLength == 0 || p.Hash == 0 {
		return boundCert{}, errors.New("HTTP.sys binding has no certificate hash")
	}
	hash, err := buf.readBytes(p.Hash, p.HashLength)
	if err != nil {
		return boundCert{}, err
	}
	store := "MY" // default store if HTTP.sys does not name one
	if p.StoreName != 0 {
		if store, err = buf.readUTF16(p.StoreName); err != nil {
			return boundCert{}, err
		}
	}
	return boundCert{Thumbprint: hash, StoreName: store}, nil
}

// queryBoundCertByIP looks up the certificate bound to IP:port.
func queryBoundCertByIP(sa *sockaddrStorage) (boundCert, error) {
	query := ipPortQuery{QueryDesc: queryExact, IPPort: sa}
	buf, err := callHTTPSysQuery(configIDSSLCert, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(&query)
	runtime.KeepAlive(sa)
	if err != nil {
		return boundCert{}, err
	}
	if len(buf)*8 < int(unsafe.Sizeof(ipPortResult{})) {
		return boundCert{}, errors.New("HTTP.sys result is too small")
	}
	result := (*ipPortResult)(unsafe.Pointer(&buf[0]))
	return readBoundCert(buf, &result.Param)
}

// queryBoundCertByHost looks up the certificate bound to hostname:port (SNI).
func queryBoundCertByHost(port int, host string) (boundCert, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return boundCert{}, errors.New("empty SNI hostname")
	}
	hostPtr, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return boundCert{}, err
	}
	// The SNI table key uses the IPv4 wildcard address; the hostname is
	// supplied separately. Verify on a real IIS box (one SNI binding on a
	// specific IP, one on "*").
	sa, err := buildSockaddr("0.0.0.0", port)
	if err != nil {
		return boundCert{}, err
	}
	query := sniQuery{QueryDesc: queryExact, IPPort: *sa, Host: hostPtr}
	buf, err := callHTTPSysQuery(configIDSSLSNICert, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(&query)
	runtime.KeepAlive(hostPtr)
	if err != nil {
		return boundCert{}, err
	}
	if len(buf)*8 < int(unsafe.Sizeof(sniResult{})) {
		return boundCert{}, errors.New("HTTP.sys SNI result is too small")
	}
	result := (*sniResult)(unsafe.Pointer(&buf[0]))
	return readBoundCert(buf, &result.Param)
}

// errCCS marks bindings that use the Centralized Certificate Store.
var errCCS = errors.New("Centralized Certificate Store binding: certificate is selected dynamically")

// findBoundCert finds the certificate HTTP.sys has bound to an IIS binding.
//
// Order: SNI table (hostname:port) first when the binding has a hostname,
// then the IP:port table. Only "record not found" moves on to the next lookup;
// real errors (access denied, API failures) are returned immediately instead
// of being hidden behind a fallback.
func findBoundCert(b IISBinding) (boundCert, error) {
	if b.SSLFlags&sslFlagCCS != 0 {
		return boundCert{}, errCCS
	}

	if b.FQDN != "" {
		found, err := queryBoundCertByHost(b.Port, b.FQDN)
		if err == nil {
			return found, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return boundCert{}, fmt.Errorf("SNI lookup: %w", err)
		}
	}

	for _, ip := range ipsToTry(b.IP) {
		sa, err := buildSockaddr(ip, b.Port)
		if err != nil {
			return boundCert{}, err
		}
		found, err := queryBoundCertByIP(sa)
		if err == nil {
			return found, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return boundCert{}, err // access denied etc. must surface
		}
	}
	return boundCert{}, windows.ERROR_FILE_NOT_FOUND
}

// -----------------------------------------------------------------------------
// Step 3: load the certificate from the Windows certificate store
// -----------------------------------------------------------------------------

// loadCertFromStore finds a certificate by SHA-1 thumbprint in LocalMachine\<storeName>.
func loadCertFromStore(storeName string, thumbprint []byte) (*x509.Certificate, error) {
	if len(thumbprint) == 0 {
		return nil, errors.New("empty certificate thumbprint")
	}

	namePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return nil, err
	}

	// Open read-only and never create a store that does not exist.
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(namePtr)),
	)
	runtime.KeepAlive(namePtr)
	if err != nil {
		return nil, fmt.Errorf("open LocalMachine\\%s: %w", storeName, err)
	}
	defer windows.CertCloseStore(store, 0)

	blob := windows.CryptHashBlob{Size: uint32(len(thumbprint)), Data: &thumbprint[0]}
	ctx, err := windows.CertFindCertificateInStore(
		store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SHA1_HASH,
		unsafe.Pointer(&blob),
		nil,
	)
	runtime.KeepAlive(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("certificate %s not found in LocalMachine\\%s: %w",
			strings.ToUpper(hex.EncodeToString(thumbprint)), storeName, err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	// IMPORTANT: copy the DER bytes into Go-owned memory. x509.ParseCertificate
	// keeps references into its input, and the Windows memory is released when
	// the context is freed above.
	der := append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// getCertForBinding runs steps 2 and 3 for one IIS binding.
func getCertForBinding(b IISBinding) (*x509.Certificate, error) {
	bound, err := findBoundCert(b)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, errors.New("no certificate is bound to this binding in HTTP.sys")
		}
		return nil, err
	}
	return loadCertFromStore(bound.StoreName, bound.Thumbprint)
}

// -----------------------------------------------------------------------------
// Building the result
// -----------------------------------------------------------------------------

// getKeyTypeAndBits returns the public key algorithm name and its size in bits.
func getKeyTypeAndBits(cert *x509.Certificate) (string, int) {
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

// signatureAlgorithmName returns a short name such as "RSA-SHA256".
func signatureAlgorithmName(a x509.SignatureAlgorithm) string {
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

// formatTimeUTC prints a time as 2006-01-02T15:04:05+00:00.
func formatTimeUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05+00:00")
}

// toCertificateResult converts a binding + certificate into the output record.
// A nil cert produces a record with Installed=false.
func toCertificateResult(b IISBinding, cert *x509.Certificate) models.CertificateResult {
	result := models.CertificateResult{
		IP:        b.IP,
		FQDN:      b.FQDN,
		Installed: cert != nil,
		Port:      b.Port,
		SANs:      []string{},
	}
	if cert == nil {
		return result
	}

	result.CommonName = cert.Subject.CommonName
	result.IssuerDN = cert.Issuer.String()
	result.SubjectDN = cert.Subject.String()
	result.KeyType, result.KeyBits = getKeyTypeAndBits(cert)
	result.NotBefore = formatTimeUTC(cert.NotBefore)
	result.NotAfter = formatTimeUTC(cert.NotAfter)
	result.SerialHex = strings.ToUpper(cert.SerialNumber.Text(16))
	result.SerialNumber = cert.SerialNumber.String()
	result.SigAlg = signatureAlgorithmName(cert.SignatureAlgorithm)

	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	result.SPKISHA256 = hex.EncodeToString(spki[:]) // lowercase

	fp256 := sha256.Sum256(cert.Raw)
	result.FingerprintSHA256 = strings.ToUpper(hex.EncodeToString(fp256[:]))

	fp1 := sha1.Sum(cert.Raw)
	result.FingerprintSHA1 = strings.ToUpper(hex.EncodeToString(fp1[:]))

	result.SANs = append(result.SANs, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		result.SANs = append(result.SANs, ip.String())
	}
	return result
}
