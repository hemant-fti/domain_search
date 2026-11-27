# SSL/TLS architecture

SSL/TLS is the product's core capability. Each concern has its own package under `pkg/ssl/`, and the web server packages (`pkg/iis`, `pkg/nginx`) only decide **where** a certificate comes from.

```
               where the certificate lives              what it is / is it OK
 ┌──────────────────────────────────────────┐   ┌──────────────────────────────┐
 │ pkg/iis/httpsys   binding → thumbprint   │   │ pkg/ssl/certificate  parse,  │
 │ pkg/ssl/store     thumbprint → cert      │──►│   describe, fingerprints     │
 │ pkg/nginx         ssl_certificate file   │   │ pkg/ssl/validate     expiry, │
 │ pkg/ssl/inspect   live TLS endpoint      │   │   hostname, chain, key pair  │
 └──────────────────────────────────────────┘   └──────────────────────────────┘
                                      │
                                      ▼
                         models.CertificateResult
```

## Implemented

### `pkg/ssl/certificate`
- `ParseDER`, `ParsePEM` (all blocks, in order), `LoadFile` (PEM or DER).
- `Describe(*x509.Certificate) models.CertificateResult` returns the subject, issuer, SANs, key type and bits, signature algorithm, serial number, validity dates, key usage and extended key usage, SHA-256 and SHA-1 fingerprints, and the SPKI SHA-256.
- `Thumbprint` returns the Windows identifier. `NormalizeThumbprint` accepts the `AB CD`, `ab:cd` and `abcd` forms.

### `pkg/ssl/validate`
- `CheckExpiry(cert, now, window)` returns `valid`, `expiring`, `expired` or `not_yet_valid`, plus the days remaining. `DefaultRenewalWindow` is 30 days, which is ACME practice.
- `Hostname(cert, host)` uses `x509.VerifyHostname`, including wildcards.
- `Chain(leaf, intermediates, opts)` uses `x509.Verify` with the system roots or a supplied pool. It wraps `ErrMissingIntermediate` when the issuer can't be found, which is the usual "server does not send its intermediate" problem.
- `KeyPair(certPEM, keyPEM)` uses `tls.X509KeyPair`.
- `Report(cert, now)` combines `Describe` and the expiry check. Inventory code uses it.

### `pkg/ssl/inspect`
- `FetchRemote(ctx, host, port, serverName)` returns the chain exactly as the endpoint serves it, plus the TLS version and cipher suite. Verification is turned off on purpose: this is inventory, so broken certificates still have to be reported. Use `validate` to judge the result.
- `Same(a, b)` compares two certificates byte for byte, for example to detect a CDN or proxy that terminates TLS instead of the origin.

### `pkg/ssl/store` (Windows)
- `FindByThumbprint(store, thumbprint)` reads from `LocalMachine\<store>`. The store is opened read-only and is never created. The DER bytes are copied into Go memory before the CryptoAPI context is freed.

### Wired into `scan`
- **IIS:** every distinct HTTPS endpoint goes through HTTP.sys, then the store, then `validate.Report`. Endpoints that fail produce `installed: false` with an `error`.
- **Nginx:** every `ssl_certificate` file goes through `LoadFile`, then `validate.Report`. Files shared by several server blocks are read once. Paths that contain Nginx variables are skipped.

## Planned (not implemented)

Each item extends an existing package or adds a new one:

| Capability | Location | Notes |
|---|---|---|
| Public-vs-local mismatch in `scan` | `internal/scan` → `inspect.FetchRemote` + `inspect.Same` | Opt-in flag, because it makes outbound connections |
| Chain completeness in inventory | `pkg/ssl/validate.Chain` with store intermediates | Needs the CA and intermediate stores read through `pkg/ssl/store` |
| Store inventory (list everything in MY/WebHosting) | `pkg/ssl/store` | `CertEnumCertificatesInStore` |
| PFX import / removal | `pkg/ssl/store` | Write operations behind an explicit API, never called implicitly |
| Renewal policy and state | new `pkg/ssl/renewal` | Eligibility from `validate.CheckExpiry`; state and history persisted by the application layer |
| Issuance | `pkg/acme` (see [acme-architecture.md](acme-architecture.md)) | |

None of these packages implement cryptographic primitives. Everything goes through `crypto/x509`, `crypto/tls` or Windows CryptoAPI.
