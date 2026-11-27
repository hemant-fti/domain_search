# Architecture

## Layers

```
cmd/hostscope ──► internal/app ──► internal/cli ──► internal/scan ──► pkg/*
                                       │                                 ▲
                                       └──► internal/cli/render ─────────┘ (pkg/models, pkg/system)
```

Dependencies point one way only, from left to right.

| Layer | Responsibility | May import |
|---|---|---|
| `cmd/hostscope` | Initializes the logger and runs the app | `internal/app`, `pkg/logger` |
| `internal/app` | Signal-aware context, runs cobra, logs each command with redacted arguments | `internal/cli`, `pkg/*` |
| `internal/cli` | Command definitions, flags, the TUI menu, writing output | `internal/scan`, `internal/cli/render`, `pkg/*` |
| `internal/cli/render` | Formats models as terminal text. It does no I/O apart from the writer it is given | `pkg/models`, `pkg/system` |
| `internal/scan` | Application logic: which inspectors run, the partial-result policy, warning classification, the report shape | `pkg/*` |
| `pkg/*` | Reusable building blocks. No application policy, no global state | `pkg/models` + the edges listed in [dependency-rules.md](dependency-rules.md) |

## How a scan flows

1. `internal/cli.NewScanCommand` creates a context bounded by `--timeout` and calls `scan.Service.Discover`.
2. `scan.hostInfo` collects the hostname, kernel and primary outbound IP (`system.PrimaryIP`).
3. `system.GetSysInfo` collects the OS, CPU, memory, disk and network. Missing fields become warnings.
4. For each platform inspector (`scan.platformInspectors`: Nginx and Apache on Linux, IIS on Windows):
   1. `Detect`: is it installed?
   2. `Running`: is it running? This is optional through the `statusInspector` interface.
   3. `Discover`: return the websites. It can return domains and an error together; that means a usable partial result and becomes a warning.
5. `scan.Normalize` merges duplicate host names across inspectors. IIS websites are kept as they are.
6. `dns.Resolver.Verify` checks each domain against the primary IP.
7. Each warning is classified into a `models.ScanError` (code, friendly message, redacted details). The CLI logs these to `application.jsonl` and the renderer shows the friendly messages.

## Error policy

- Reusable packages return wrapped errors (`%w`) and never log.
- A **partial result** is a non-nil slice together with a non-nil error. `internal/scan` keeps the data and records the error as a warning. A nil slice with an error is a failure.
- Only cancellation (Ctrl+C or `--timeout`) aborts a whole scan. A failing inspector is a warning.
- Every external command and network call takes a `context.Context`.

## Platform boundaries

Platform code lives only in files with build constraints (`*_linux.go`, `*_windows.go`, or `//go:build`). Cross-platform logic that has a Windows-only data source is split into a pure function plus a platform collector. For example, `pkg/iis/domains.go` builds the domain records and `pkg/iis/iis_windows.go` gathers the data, so the logic can be tested on Linux.

| Concern | Linux | Windows |
|---|---|---|
| Is the web server installed? | `exec.LookPath` | `appcmd.exe` or the `HKLM\SOFTWARE\Microsoft\InetStp` registry key (`x/sys/windows/registry`) |
| Is it running? | scan `/proc/*/comm` (`system.ProcessRunning`) | service manager query of W3SVC (`system.ServiceRunning`) |
| Where certificates come from | PEM/DER files | HTTP.sys + the LocalMachine store |
