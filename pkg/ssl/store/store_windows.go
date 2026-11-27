//go:build windows

package store

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindByThumbprint returns the certificate with the given SHA-1 thumbprint
// from LocalMachine\<storeName>. The store is opened read-only and is never
// created. An empty storeName means DefaultStore.
func FindByThumbprint(storeName string, thumbprint []byte) (*x509.Certificate, error) {
	if len(thumbprint) == 0 {
		return nil, errors.New("empty certificate thumbprint")
	}
	if storeName == "" {
		storeName = DefaultStore
	}

	namePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("%w: %s in LocalMachine\\%s: %w", ErrNotFound,
			strings.ToUpper(hex.EncodeToString(thumbprint)), storeName, err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	// Copy the DER bytes into Go memory: x509.ParseCertificate keeps
	// references into its input, and the Windows memory is freed above.
	der := append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate from LocalMachine\\%s: %w", storeName, err)
	}
	return cert, nil
}
