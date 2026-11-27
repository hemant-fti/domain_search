# IIS architecture

## Implemented

```
pkg/iis               glue: Inspector (Detect, Running, Discover) and buildDomains
pkg/iis/config        applicationHost.config parsing                     (cross-platform)
pkg/iis/httpsys       HTTP.sys binding → certificate thumbprint + store   (Windows)
pkg/ssl/store         thumbprint → *x509.Certificate                     (Windows)
pkg/ssl/validate      Report: metadata + expiry status
```

### Discovery: `pkg/iis/config`
- `Path()` finds `applicationHost.config`. A 32-bit process on 64-bit Windows reads it through `Sysnative`.
- `Parse`/`Load` read the file **once** and return every site with:
  - its bindings: protocol, IP, port, host, `sslFlags`, and the config `certificateHash` and store
  - the root physical path
  - the URL Rewrite proxy target (site `<location>` rules first, then global)
- `ParseBindingInformation` is the single parser for `ip:port:host` (IPv6 `[addr]` supported). Malformed http/https bindings are reported. Other protocols such as `net.tcp 808:*` are skipped.
- `NormalizeIP` / `IsWildcardIP`: `""`, `*`, `0.0.0.0`, `::` and `[::]` all mean "all unassigned".
- `ExpandPath` expands `%VAR%` references such as `%SystemDrive%`.

### Bindings: `pkg/iis/httpsys`
- `Open()` → `Session.Lookup(ip, port, host, sslFlags)` → `Bound{Thumbprint, StoreName}`.
- Lookup order:
  1. The SNI table (`hostname:port`), if the binding has a host.
  2. `IP:port`.
  3. The wildcard `0.0.0.0:port` / `[::]:port`.
- Only "not found" falls through to the next table. Access-denied and other API errors are returned.
- Centralized Certificate Store bindings (`sslFlags & 2`) return `ErrCCS`, because the certificate is chosen per request.
- Pointers that HTTP.sys returns into the output buffer are bounds-checked before they are read.

### Certificates
- `pkg/iis` resolves each **distinct** HTTPS endpoint once: HTTP.sys, then `store.FindByThumbprint`, then `validate.Report`.
- Endpoints that fail still get a record with `installed: false` and `error`.
- `Domain.SSLCertificate` is the config `certificateHash` when present. Otherwise it is the HTTP.sys thumbprint.

### State
- **Installed:** `appcmd.exe` exists, or the `HKLM\SOFTWARE\Microsoft\InetStp\InstallPath` registry value is set.
- **Running:** the W3SVC service state, read from the service manager with `SC_MANAGER_CONNECT` only, so administrator rights aren't needed.
- **Site state:** `Get-Website` via PowerShell, bounded by the command context. If it fails, the site state shows `Unknown` and a warning is recorded.

### Partial results
`Discover` returns the domains together with a joined error that covers:
- malformed bindings
- site status unavailable
- each certificate that couldn't be read
- local IP enumeration failures

`internal/scan` turns these into warnings.

## Planned: `pkg/iis/management`

This package doesn't exist yet. It will hold **write** operations, kept apart from discovery so a read-only scan can never change a server.

| Operation | Mechanism |
|---|---|
| Assign a certificate to an endpoint | `HttpSetServiceConfiguration` / `HttpUpdateServiceConfiguration` (SNI or IP:port), mirroring `httpsys` |
| Create or update an HTTPS binding in a site | Edit `applicationHost.config` through the IIS configuration API (`Microsoft.ApplicationHost.WritableAdminManager` COM) rather than writing the XML directly |
| Replace a certificate across all bindings that use a thumbprint | Built from the two operations above + `config.Parse` |
| Validate configuration | Re-read through `config` + `httpsys`, then confirm with `ssl/inspect.FetchRemote` |

Design constraints:
- Every mutating call takes a context and returns what it changed, so it can be rolled back.
- Nothing in `pkg/iis` discovery imports `management`.
- Certificate import belongs in `pkg/ssl/store`, not here.

## Known limitations

- CCS bindings are listed but their certificate isn't resolved.
- Site state needs the WebAdministration PowerShell module.
- The HTTP.sys SNI lookup uses the IPv4 wildcard key, which matches how IIS registers SNI bindings. It should be confirmed on a host that has SNI bindings on a specific IP.
- None of this has been verified at runtime. The Windows code is compiled and vetted from Linux (`make cross`, `make vet`), but its unit tests (`*_windows_test.go`) have to be run on a Windows host.
