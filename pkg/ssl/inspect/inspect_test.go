package inspect_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"domain-search/pkg/ssl/inspect"
	"domain-search/pkg/ssl/internal/certtest"
)

func TestFetchRemoteReturnsServedChain(t *testing.T) {
	issued := certtest.New(t, certtest.Options{CommonName: "served.test", DNSNames: []string{"served.test"}})

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{issued.Cert.Raw},
		PrivateKey:  issued.Key,
	}}}
	srv.StartTLS()
	defer srv.Close()

	host, portText, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)

	ep, err := inspect.FetchRemote(context.Background(), host, port, "served.test")
	if err != nil {
		t.Fatal(err)
	}
	if !inspect.Same(ep.Leaf(), issued.Cert) {
		t.Fatalf("served leaf %q is not the configured certificate", ep.Leaf().Subject.CommonName)
	}
	if ep.TLSVersion == "" || ep.CipherSuite == "" {
		t.Errorf("TLS details missing: %+v", ep)
	}

	other := certtest.New(t, certtest.Options{CommonName: "other"})
	if inspect.Same(ep.Leaf(), other.Cert) || inspect.Same(nil, issued.Cert) {
		t.Error("Same reported a mismatch as equal")
	}
}

func TestFetchRemoteFailsOnClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	if _, err := inspect.FetchRemote(context.Background(), "127.0.0.1", port, ""); err == nil {
		t.Fatal("expected connection error")
	}
}

func TestFetchRemoteHonoursContext(t *testing.T) {
	// A listener that accepts but never speaks TLS forces the handshake to wait.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = inspect.FetchRemote(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "x.test")
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("FetchRemote ignored the context deadline (%s)", time.Since(start))
	}
}
