# Dependency rules

`tests/architecture_test.go` enforces these rules for both `GOOS=linux` and `GOOS=windows`. Run it with `make check-deps`.

## Rules

1. `pkg/**` never imports `internal/**` or `cmd/**`.
2. `pkg/**` never imports `pkg/logger`. Reusable code returns errors; the application decides what to log.
3. `pkg/models` imports only the standard library.
4. A `pkg/` package may import only the project packages listed for it below. To add an edge, update the test and this file in the same change, and give the reason.
5. There are no import cycles. The Go compiler enforces this; the layering keeps it easy.
6. External libraries stay behind the package that needs them. For example, gopsutil appears only in `pkg/system` and `x/sys/windows` only in Windows files.

## Allowed project imports for `pkg/`

| Package | May import |
|---|---|
| `pkg/models`, `pkg/logger`, `pkg/security`, `pkg/tui` | — |
| `pkg/iis/config`, `pkg/iis/httpsys` | — |
| `pkg/ssl/inspect`, `pkg/ssl/store` | — |
| `pkg/ssl/certificate` | `pkg/models` |
| `pkg/ssl/validate` | `pkg/models`, `pkg/ssl/certificate` |
| `pkg/dns`, `pkg/system` | `pkg/models` |
| `pkg/apache` | `pkg/models`, `pkg/system` |
| `pkg/nginx` | `pkg/models`, `pkg/system`, `pkg/ssl/certificate`, `pkg/ssl/validate` |
| `pkg/iis` | `pkg/models`, `pkg/system`, `pkg/iis/config`, `pkg/iis/httpsys`, `pkg/ssl/certificate`, `pkg/ssl/store`, `pkg/ssl/validate` |

`pkg/ssl/internal/certtest` is a test helper. It is internal to `pkg/ssl`, so the Go toolchain itself stops anything outside `pkg/ssl` from importing it.

## External dependencies

| Module | Used by | Why it is kept |
|---|---|---|
| `github.com/spf13/cobra` | `internal/cli` | CLI framework |
| `charm.land/bubbletea/v2`, `charm.land/lipgloss/v2` | `pkg/tui` | Interactive menu |
| `github.com/fatih/color` | `internal/cli/render` | Terminal colors with Windows console and `NO_COLOR` support. Overlaps with lipgloss; see the technical debt section |
| `github.com/shirou/gopsutil/v4` | `pkg/system` | Cross-platform CPU, memory, host and Windows disk metrics |
| `golang.org/x/sys` | `pkg/system`, `pkg/iis/httpsys`, `pkg/ssl/store` | Windows APIs (HTTP.sys, CryptoAPI, registry, SCM) and Linux `statfs` |

X.509, TLS and DNS use only the standard library (`crypto/x509`, `crypto/tls`, `net`).

## Technical debt

- `fatih/color` and `lipgloss` both style terminal output. Moving `render` to lipgloss would remove a direct dependency.
- `pkg/system.PrimaryIP` finds the outbound interface by opening a UDP socket toward `1.1.1.1`. No packets are sent, but on air-gapped hosts it reports "network unreachable".
