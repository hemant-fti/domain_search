// Package inspect fetches the certificates a TLS endpoint actually serves and
// compares them with locally installed ones.
//
// Use it to detect certificate mismatches, for example a CDN or proxy that
// terminates TLS in front of the origin server.
package inspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DefaultTimeout bounds a remote fetch when the context has no deadline.
const DefaultTimeout = 5 * time.Second

// Endpoint is what a TLS server presented during the handshake.
type Endpoint struct {
	// Chain is the certificate chain exactly as sent, leaf first.
	Chain       []*x509.Certificate
	TLSVersion  string
	CipherSuite string
}

// Leaf returns the served end-entity certificate.
func (e Endpoint) Leaf() *x509.Certificate {
	if len(e.Chain) == 0 {
		return nil
	}
	return e.Chain[0]
}

// FetchRemote connects to host:port and returns what the server presents for
// serverName (SNI). An empty serverName uses host.
//
// Verification is deliberately disabled: this is inventory, so expired,
// self-signed and mismatched certificates must still be reported. Use package
// validate to judge the result.
func FetchRemote(ctx context.Context, host string, port int, serverName string) (Endpoint, error) {
	if serverName == "" {
		serverName = host
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec // inventory, see doc comment
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return Endpoint{}, fmt.Errorf("TLS handshake with %s:%d: %w", host, port, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return Endpoint{}, errors.New("unexpected connection type")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Endpoint{}, fmt.Errorf("%s:%d presented no certificate", host, port)
	}
	return Endpoint{
		Chain:       state.PeerCertificates,
		TLSVersion:  tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}, nil
}

// Same reports whether two certificates are byte-for-byte identical.
func Same(a, b *x509.Certificate) bool {
	return a != nil && b != nil && a.Equal(b)
}
