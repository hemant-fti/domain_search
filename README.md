# DomainScout

DomainScout is a Go command-line tool that scans the local Linux server for Nginx and Apache website configuration, checks discovered domain names through DNS, and collects server and system information.

The scan runs on the machine being inspected. This repository currently provides a local CLI; it does not include an HTTP API or an SSH client.

## Requirements

- Go 1.26 or later to build from source (see `go.mod`).
- A Linux host with `/bin/sh` to run a scan.
- Nginx and/or Apache command-line tools to inspect those services. Missing tools or inaccessible configuration may result in warnings or incomplete results.
- DNS/network access for DNS verification.

Root access is not required for every field. Some configuration checks retry with `sudo -n`; run with appropriate privileges if you need to inspect protected service configuration.

## Build

Build for the current host:

```bash
go build -o hostscope ./cmd/hostscope
```

Build a Linux AMD64 binary from a host with GNU Make:

```bash
make build-app
```

That target writes `dist/hostscope-linux-amd64`. Copy the binary to the Linux server you want to scan. Go is not needed on the target server.

## Run a scan

```bash
# Human-readable report
./hostscope scan

# Indented JSON
./hostscope scan --json

# Compact JSON
./hostscope scan --compact

# Save JSON to a file
./hostscope scan --json --output scan.jsonl

# Set the maximum scan duration
./hostscope scan --timeout 3m

# Print the CLI version
./hostscope version
```

The default scan timeout is two minutes. `--pretty` also selects JSON output; `--compact` selects compact JSON. JSON scan results are written to stdout unless `--output` is specified; scan records are also appended to `scan-results.jsonl` in the current working directory as JSON Lines, preserving earlier runs. Warning and error events are recorded separately in `scan-errors.jsonl`. On an error, human-readable diagnostics go to stderr; JSON-mode errors are written as a JSON object to stdout. The CLI exits with a non-zero status.

The human-readable report includes the scan status, server overview, detected services, website configurations, DNS results, system information, and warnings.

## Command reference

The CLI command hierarchy is:

```text
hostscope
├── scan
├── system info|cpu|memory|disk|network|uptime
├── web list|nginx|apache|status
├── domains list|nginx|apache|dns
├── ports list|tcp|udp
├── services list|status <service>
├── ssl list|check
├── config nginx|apache
└── version
```

Commands that return discovery results support `--json`, `--pretty`, `--compact`, `--timeout`, and `--output FILE`. `--pretty` implies JSON; `--compact` emits JSON without indentation. `scan` retains its existing output formats and timeout option.

Examples:

```bash
# System information; focused commands collect only their requested category
hostscope system info --json
hostscope system info --all
hostscope system info --details
hostscope system cpu
hostscope system memory
hostscope system disk --path /
hostscope system network
hostscope system uptime

# Installed/running web servers and parsed virtual hosts
hostscope web list
hostscope web nginx --version --config --domains
hostscope web apache
hostscope web status
hostscope domains list --server nginx --port 443 --aliases
hostscope domains nginx --config-path /etc/nginx/sites-enabled/site
hostscope domains apache --document-root /var/www/site

# DNS queries use the configured system resolver; these do not enumerate
# authoritative DNS records.
hostscope domains dns --domain example.com --record A
hostscope domains dns --domain example.com --record AAAA
hostscope domains dns --domain example.com --record MX
hostscope domains dns --domain example.com --record NS
hostscope domains dns --domain example.com --record TXT
hostscope domains get-data-by-name --name example.com

# Local sockets only; this does not scan remote hosts
hostscope ports list --state listening --process
hostscope ports tcp --port 443 --pid 1234
hostscope ports udp --range 8000-9000
hostscope ports list --all --protocol tcp

# Linux systemd services
hostscope services list --running
hostscope services list --stopped --enabled
hostscope services status nginx

# Certificates are read from local certificate paths discovered in web
# server configuration. Private keys and remote TLS endpoints are not read.
hostscope ssl list --domain example.com
hostscope ssl check --expired
hostscope ssl check --expiring-in 30d

# Native config tests do not print configuration file contents.
hostscope config nginx --test --virtual-hosts
hostscope config apache --test
```

DNS lookup supports only A, AAAA, MX, NS, and TXT records. Ports are local TCP/UDP sockets. `--all` includes non-listening TCP connections; UDP has no TCP-style listening state and is reported as bound. SSL commands inspect certificates referenced by local configuration and do not probe remote TLS services. Service management commands require Linux with systemd. Web-server discovery/configuration commands require Linux and the corresponding Nginx or Apache tools; protected configuration may require appropriate privileges. System metrics and local socket listing use the existing gopsutil collectors and depend on host permissions/platform support.

Not implemented: authoritative DNS zone enumeration, remote port scanning, remote TLS certificate checks, Windows service-manager integration, and discovery of web servers other than Nginx and Apache. Such operations are not implied by similarly named local inspection commands.

## JSON output

The scan JSON response includes:

- `status`, `scanned_at`, and `warnings`.
- `server`: hostname, operating system, kernel, and primary IP address.
- `detected_services` and `total_domains`.
- `servers`: detected web services, their running state, and reported domains, aliases, configuration files, document roots, and listening ports.
- `system`: network addresses, OS and CPU details, uptime, user, timezone, disk, and memory information.
- `domains`: discovered website configuration and DNS status, including resolved IP addresses.

Disk and memory fields ending in `_gb` are reported in GiB (bytes divided by 1024^3). DNS matching compares resolved addresses with the server's detected primary IP; a DNS match does not establish that a website is reachable.

## Checks

```bash
go test ./...
go vet ./...
```

## Current limitations

- Scans run locally and require `/bin/sh`; remote SSH scanning and an HTTP API are not implemented.
- Nginx discovery uses `nginx -T` and basic configuration parsing. It may require elevated privileges and may not recognize every valid configuration pattern.
- Apache discovery relies on `apachectl -S` or `httpd -S`; it does not fully parse every virtual-host directive.
- Only Nginx and Apache website configurations are inspected. Caddy and Docker discovery are not currently implemented.
- DNS results can differ from a simple server-IP comparison when a domain uses NAT, load balancers, CDNs, or multiple public IPs.
- The tool does not store credentials. Scan history is appended locally as JSON Lines in `scan-results.jsonl`.

## Security

- Run the scanner with only the privileges needed to read the relevant service configuration.
- DNS verification requires network access.
