# Package responsibilities

## Application (`internal/`)

| Package | Owns | Does not own |
|---|---|---|
| `internal/app` | Process lifecycle, SIGINT/SIGTERM, logging each command with redacted args | Command logic |
| `internal/cli` | Cobra commands, the `--timeout` flag, the TUI menu, writing results to stdout and `application.jsonl` | Parsing, discovery, DNS, certificates |
| `internal/cli/render` | Human-readable layout, colors, tables | Collecting data, classifying errors |
| `internal/scan` | The `Inspector` interface, the platform inspector list, partial-result policy, domain normalization, warning classification (`report.go`), DNS verification of results | Parsing any web server's config |

## Reusable (`pkg/`)

| Package | Owns | Platform |
|---|---|---|
| `pkg/models` | Shared result types (`Domain`, `Binding`, `CertificateResult`, `DNSResult`, `Result`, `SystemInfo`) and status constants | all |
| `pkg/nginx` | Parsing `nginx -T` output, `listen` ports, loading `ssl_certificate` files (`LoadCertificates`), the inspector | parsing: all; inspector: Linux |
| `pkg/apache` | Parsing `apachectl -S` output, document roots, the inspector | parsing: all; inspector: Linux |
| `pkg/iis` | Combines config, HTTP.sys and store into one domain per IIS website; IIS detection, running state, site state | build logic: all; inspector: Windows |
| `pkg/iis/config` | Reading `applicationHost.config`: sites, bindings, sslFlags, physical paths, URL Rewrite proxy targets. This is the **only** `bindingInformation` parser | all |
| `pkg/iis/httpsys` | Read-only HTTP.sys lookups: binding → certificate thumbprint + store name | Windows |
| `pkg/ssl/certificate` | Parsing PEM/DER, `Describe` (metadata), fingerprints, thumbprint normalization | all |
| `pkg/ssl/inspect` | `FetchRemote`: the chain a TLS endpoint serves; `Same` for mismatch detection | all |
| `pkg/ssl/validate` | Expiry status, hostname coverage, chain/trust verification (missing intermediate detection), cert/key pairing; `Report` = Describe + expiry | all |
| `pkg/ssl/store` | Read-only `FindByThumbprint` in LocalMachine stores | Windows (other platforms return `ErrUnsupported`) |
| `pkg/dns` | Resolving addresses and checking them against the server IP; the lookup client is injectable | all |
| `pkg/system` | Host, OS, CPU, memory, disk, network, local IPs, process (`/proc`) and Windows service/registry state | all, with per-OS files |
| `pkg/security` | Redacting secrets from args and free text | all |
| `pkg/logger` | slog-based JSON logging with a process-wide logger. **Only the application layer uses it** | all |
| `pkg/tui` | A generic Bubble Tea menu | all |

## Where new work goes

| Capability | Package |
|---|---|
| Apache `SSLCertificateFile` inventory | `pkg/apache` (reuse `pkg/ssl/validate.Report`) |
| Local-vs-public certificate comparison in scans | `internal/scan`, calling `pkg/ssl/inspect` |
| Installing a PFX into LocalMachine\MY | `pkg/ssl/store` |
| Creating or updating IIS HTTPS bindings | new `pkg/iis/management` |
| ACME issuance and renewal | new `pkg/acme`; renewal policy in `pkg/ssl/validate` / new `pkg/ssl/renewal` |
