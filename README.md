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
go build -o domain-scout ./cmd/agent
```

Build a Linux AMD64 binary from a host with GNU Make:

```bash
make build-linux-amd64
```

That target writes `dist/domain-scout-linux-amd64`. Copy the binary to the Linux server you want to scan. Go is not needed on the target server.

## Run a scan

```bash
# Human-readable report
./domain-scout scan

# Indented JSON
./domain-scout scan --json

# Compact JSON
./domain-scout scan --compact

# Set the maximum scan duration
./domain-scout scan --timeout 3m

# Print the CLI version
./domain-scout version
```

The default scan timeout is two minutes. `--pretty` also selects JSON output; `--compact` selects compact JSON. The CLI writes scan results to stdout. On a scan or command error it writes a JSON error object to stdout and exits with a non-zero status.

The human-readable report includes the scan status, server overview, detected services, website configurations, DNS results, system information, and warnings.

## JSON output

The JSON response includes:

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
- The tool is stateless and does not store scan history or credentials.

## Security

- Run the scanner with only the privileges needed to read the relevant service configuration.
- DNS verification requires network access.
