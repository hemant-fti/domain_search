# ACME architecture (planned)

> **Status: design only.** No ACME code or dependency exists yet. This document records the decisions so that implementation starts from an agreed shape.

## Library choice

| Option | What it gives | What we would still have to build |
|---|---|---|
| `golang.org/x/crypto/acme` | The ACME (RFC 8555) protocol: accounts, orders, authorizations, finalize | Solving challenges, DNS provider integrations, retry and polling, renewal bookkeeping |
| `github.com/go-acme/lego` (latest major version at implementation time) | All of the above, plus HTTP-01 and DNS-01 solvers, 150+ DNS provider integrations, multiple CAs including EAB for ZeroSSL, and ARI renewal info | Only our integration |

**Decision: use lego.** DNS-01 with many providers is a stated requirement, and lego already covers it. Writing it ourselves on top of `x/crypto/acme` would duplicate a mature library. The dependency is added when the first ACME feature is built, not before.

## Package layout (when implemented)

```
pkg/acme/            the only package that imports lego
  account.go         account registration, key load/store (key storage via an interface)
  issue.go           Issue(ctx, Request) → certificate chain + private key (PEM)
  renew.go           Renew(ctx, existing) → new chain
  challenge.go       which solver to use: HTTP-01 (IIS webroot or standalone) or DNS-01 (provider name + config)
```

Rules:
- `pkg/acme` returns PEM bytes and parsed `*x509.Certificate`. It never touches IIS or the Windows store.
- CA selection is configuration (directory URL + optional EAB credentials). Let's Encrypt and ZeroSSL are just two configurations.
- Secrets (account keys, DNS provider credentials) are passed in through interfaces and never stored by `pkg/acme`. The application layer chooses where they live, for example DPAPI-protected files on Windows.
- Every call takes a `context.Context`.

## End-to-end flow (target)

```
internal/<renew command or scheduler>
   │ 1. eligibility: ssl/validate.CheckExpiry(cert, now, window)  (later: ARI)
   ▼
pkg/acme.Issue / Renew ──► PEM chain + key
   │ 2. verify:  ssl/validate.KeyPair, ssl/validate.Chain
   ▼
pkg/ssl/store.Import (PFX into LocalMachine\MY or WebHosting)   ── planned
   │ 3. thumbprint
   ▼
pkg/iis/management.Rebind(binding, thumbprint)                 ── planned
   │ 4. confirm
   ▼
pkg/ssl/inspect.FetchRemote + inspect.Same(new cert)  → success / rollback
```

HTTP-01 on IIS: the solver writes `/.well-known/acme-challenge/<token>` under the site's physical path (`models.Domain.Path`, already discovered). If that is not possible, it uses lego's standalone server on a free port behind a temporary binding.

## Out of scope for the first ACME milestone

- Scheduling. Use Windows Task Scheduler to call a `hostscope renew` command before building an in-process scheduler.
- Multi-server certificate distribution.
