# DomainScout (`hostscope`)

`hostscope` is a Go command-line tool that runs on a server and reports:

- which web servers are installed and running (Nginx and Apache on Linux, IIS on Windows)
- the websites and virtual hosts they serve
- whether each domain's DNS points at this server
- the TLS certificates those sites use: issuer, SANs, validity, expiry status and fingerprints
- system health: OS, CPU, memory, disk and uptime

It is the first phase of an SSL/TLS certificate management tool focused on Windows Server and IIS. See [Roadmap](#roadmap).

## Supported platforms

| Platform | Web servers | Certificate source |
|---|---|---|
| Linux (amd64) | Nginx, Apache | Nginx `ssl_certificate` files |
| Windows Server (amd64) | IIS | HTTP.sys bindings + LocalMachine certificate store |

## Requirements

- Go 1.26 or later to build (see `go.mod`). The target server does not need Go.
- **Linux**
  - The `nginx` and/or `apachectl`/`httpd` tools must be on `PATH`.
  - Reading protected configuration needs root. Hostscope retries with `sudo -n`.
- **Windows**
  - IIS must be installed.
  - Run as Administrator to read HTTP.sys certificate bindings and the LocalMachine store.
  - Site state (Started/Stopped) uses the WebAdministration PowerShell module.
- DNS access is needed for DNS verification.

## Build

```bash
make build            # current platform → ./hostscope (or hostscope.exe)
make build-linux      # → ./hostscope              (linux/amd64, static)
make build-windows    # → ./hostscope-windows-amd64.exe
```

Or build directly:

```bash
go build -o hostscope ./cmd/hostscope
```

## Commands

```bash
hostscope                 # interactive menu (same as `hostscope tui`)
hostscope scan            # full report: services, websites, DNS, certificates, system
hostscope domains list    # websites from every detected web server
hostscope domains get-data-by-name example.com
hostscope system          # system report
hostscope system cpu | memory | disk | uptime
hostscope version         # prints {"version": "..."}
```

Every data command accepts `--timeout` (default `2m`).

Output is human-readable text on stdout. Each command's structured result is also appended as one JSON line to `application.jsonl` in the current directory, along with diagnostic logs and warning events. Secrets in arguments and error details are redacted.

## What a scan reports about certificates

Each certificate result contains the following fields. The JSON key is in brackets.

| Field | Contents |
|---|---|
| Installed (`installed`) | `false` when the certificate could not be read; `error` explains why. |
| Identity | `common_name`, `subject_dn`, `issuer_dn`, `sans` |
| Key | `key_type`, `key_bits`, `sig_alg`, `key_usage`, `ext_key_usage` |
| Validity | `not_before`, `not_after`, `expiry_status`, `days_remaining` |
| Identifiers | `serial_number`, `serial_hex`, `fingerprint_sha256`, `fingerprint_sha1` (the Windows thumbprint), `spki_sha256` |
| Endpoint | `ip`, `fqdn`, `port`, `paths.fullchain` (the file path for Nginx; `null` for the Windows store) |

`expiry_status` is one of:
- `valid`
- `expiring`: within 30 days of `not_after`
- `expired`
- `not_yet_valid`

## Architecture

```
cmd/hostscope        entry point
internal/app         signal handling, command execution, redacted command logging
internal/cli         cobra commands and the interactive menu (presentation only)
internal/cli/render  human-readable output
internal/scan        orchestration: runs inspectors, DNS checks, builds the report
pkg/models           shared domain types
pkg/nginx            Nginx virtual hosts and certificate files
pkg/apache           Apache virtual hosts
pkg/iis              IIS websites + bound certificates
pkg/iis/config       applicationHost.config parsing (cross-platform)
pkg/iis/httpsys      HTTP.sys certificate binding lookup (Windows)
pkg/ssl/certificate  X.509 parsing and metadata
pkg/ssl/inspect      certificates served by a live TLS endpoint
pkg/ssl/validate     expiry, hostname, chain and key-pair checks
pkg/ssl/store        Windows certificate store lookup
pkg/dns              DNS resolution and server-IP verification
pkg/system           OS, CPU, memory, disk, network, process and service state
pkg/security         secret redaction
pkg/logger           structured JSON logging (application layer only)
pkg/tui              generic keyboard menu
```

Packages under `pkg/` never import `internal/` and never use the global logger. Each one can be used and tested on its own. `go test ./tests/` enforces these rules.

More detail is in [docs/](docs/):

- [architecture.md](docs/architecture.md): layers and how a scan flows
- [package-responsibilities.md](docs/package-responsibilities.md)
- [dependency-rules.md](docs/dependency-rules.md)
- [ssl-architecture.md](docs/ssl-architecture.md)
- [acme-architecture.md](docs/acme-architecture.md): planned
- [iis-architecture.md](docs/iis-architecture.md)

## Development

```bash
make test        # unit tests
make test-race   # with the race detector (needs a C compiler)
make vet         # go vet for linux and windows
make check-deps  # package dependency rules
make cross       # build everything and compile Windows tests
make check       # all of the above + gofmt
```

Windows-only code (`*_windows.go`) is compiled and vetted from Linux by `make cross` and `make vet`. Its tests must run on Windows.

## Roadmap

**Implemented**
- Web server, website and binding discovery.
- DNS verification.
- Certificate inventory: IIS through HTTP.sys and the certificate store; Nginx through certificate files.
- Expiry status.
- Chain, hostname and key-pair validation helpers.
- Fetching the certificate a public endpoint serves.

**Planned**
- ACME issuance and renewal (Let's Encrypt, ZeroSSL; HTTP-01 and DNS-01).
- Renewal scheduling and history.
- Certificate installation into the Windows store.
- IIS HTTPS binding creation and replacement.
- Local-vs-public certificate mismatch reporting in `scan`.
- Apache `SSLCertificateFile` inventory.

The planned designs are in [docs/acme-architecture.md](docs/acme-architecture.md) and [docs/iis-architecture.md](docs/iis-architecture.md).
