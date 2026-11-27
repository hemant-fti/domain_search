//go:build windows

// Package httpsys asks HTTP.sys, the Windows kernel HTTP driver, which
// certificate is bound to an IIS binding.
//
// HTTP.sys is the source of truth for IIS TLS: the certificate is not stored
// in applicationHost.config. This package only reads configuration; it never
// changes bindings. Reading requires Administrator rights.
//
// Limitation: Centralized Certificate Store (CCS) bindings select the
// certificate dynamically and are reported with ErrCCS.
package httpsys

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sslFlagCCS mirrors config.SSLFlagCCS; duplicated to keep this package
// independent of the config parser.
const sslFlagCCS = 2

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

// Session is an initialized connection to the HTTP Server API configuration.
// It is not safe for concurrent use.
type Session struct{ closed bool }

// Open initializes the HTTP Server API for reading its configuration.
// Callers must Close the session.
func Open() (*Session, error) {
	if err := httpapi.Load(); err != nil {
		return nil, fmt.Errorf("load httpapi.dll: %w", err)
	}
	r, _, _ := procHTTPInitialize.Call(httpAPIVersion2, httpInitializeConfig, 0)
	if rc := uint32(r); rc != 0 { // the Windows API returns a 32-bit code
		return nil, fmt.Errorf("HttpInitialize: %w", windows.Errno(rc))
	}
	return &Session{}, nil
}

// Close releases the HTTP Server API. It is safe to call more than once.
func (s *Session) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	r, _, _ := procHTTPTerminate.Call(httpInitializeConfig, 0)
	if rc := uint32(r); rc != 0 {
		return fmt.Errorf("HttpTerminate: %w", windows.Errno(rc))
	}
	return nil
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

// Bound is what HTTP.sys reports for a binding: which certificate, in which store.
type Bound struct {
	Thumbprint []byte // SHA-1
	StoreName  string // under LocalMachine, e.g. "MY" or "WebHosting"
}

// readBoundCert extracts the thumbprint and store name from an HTTP.sys result.
func readBoundCert(buf kernelBuffer, p *sslParam) (Bound, error) {
	if p.HashLength == 0 || p.Hash == 0 {
		return Bound{}, errors.New("HTTP.sys binding has no certificate hash")
	}
	hash, err := buf.readBytes(p.Hash, p.HashLength)
	if err != nil {
		return Bound{}, err
	}
	store := "MY" // default store if HTTP.sys does not name one
	if p.StoreName != 0 {
		if store, err = buf.readUTF16(p.StoreName); err != nil {
			return Bound{}, err
		}
	}
	return Bound{Thumbprint: hash, StoreName: store}, nil
}

// queryBoundCertByIP looks up the certificate bound to IP:port.
func queryBoundCertByIP(sa *sockaddrStorage) (Bound, error) {
	query := ipPortQuery{QueryDesc: queryExact, IPPort: sa}
	buf, err := callHTTPSysQuery(configIDSSLCert, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(&query)
	runtime.KeepAlive(sa)
	if err != nil {
		return Bound{}, err
	}
	if len(buf)*8 < int(unsafe.Sizeof(ipPortResult{})) {
		return Bound{}, errors.New("HTTP.sys result is too small")
	}
	result := (*ipPortResult)(unsafe.Pointer(&buf[0]))
	return readBoundCert(buf, &result.Param)
}

// queryBoundCertByHost looks up the certificate bound to hostname:port (SNI).
func queryBoundCertByHost(port int, host string) (Bound, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return Bound{}, errors.New("empty SNI hostname")
	}
	hostPtr, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return Bound{}, err
	}
	// The SNI table key uses the IPv4 wildcard address; the hostname is
	// supplied separately. Verify on a real IIS box (one SNI binding on a
	// specific IP, one on "*").
	sa, err := buildSockaddr("0.0.0.0", port)
	if err != nil {
		return Bound{}, err
	}
	query := sniQuery{QueryDesc: queryExact, IPPort: *sa, Host: hostPtr}
	buf, err := callHTTPSysQuery(configIDSSLSNICert, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(&query)
	runtime.KeepAlive(hostPtr)
	if err != nil {
		return Bound{}, err
	}
	if len(buf)*8 < int(unsafe.Sizeof(sniResult{})) {
		return Bound{}, errors.New("HTTP.sys SNI result is too small")
	}
	result := (*sniResult)(unsafe.Pointer(&buf[0]))
	return readBoundCert(buf, &result.Param)
}

// ErrCCS marks bindings that use the Centralized Certificate Store.
var ErrCCS = errors.New("Centralized Certificate Store binding: certificate is selected dynamically")

// ErrNotBound means HTTP.sys has no certificate registered for the binding.
var ErrNotBound = errors.New("no certificate is bound to this binding in HTTP.sys")

// Lookup finds the certificate HTTP.sys has bound to an IIS binding.
//
// ip is the binding IP ("*" or "" for all unassigned), host the binding host
// name (may be empty) and sslFlags the IIS sslFlags value.
//
// Order: SNI table (hostname:port) first when the binding has a hostname,
// then the IP:port table. Only "record not found" moves on to the next lookup;
// real errors (access denied, API failures) are returned immediately instead
// of being hidden behind a fallback.
func (s *Session) Lookup(ip string, port int, host string, sslFlags uint32) (Bound, error) {
	if s == nil || s.closed {
		return Bound{}, errors.New("HTTP.sys session is closed")
	}
	if sslFlags&sslFlagCCS != 0 {
		return Bound{}, ErrCCS
	}

	if host != "" {
		found, err := queryBoundCertByHost(port, host)
		if err == nil {
			return found, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return Bound{}, fmt.Errorf("SNI lookup: %w", err)
		}
	}

	for _, candidate := range ipsToTry(ip) {
		sa, err := buildSockaddr(candidate, port)
		if err != nil {
			return Bound{}, err
		}
		found, err := queryBoundCertByIP(sa)
		if err == nil {
			return found, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return Bound{}, err // access denied etc. must surface
		}
	}
	return Bound{}, ErrNotBound
}
