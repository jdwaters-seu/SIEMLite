# Threat model: SIEMLite

SIEMLite is a self-hosted security information and event management (SIEM) system. One Go binary (pure Go, no CGO)
that stores events in SQLite with FTS5 full-text search, serves an embedded web UI and a JSON API over HTTPS, accepts
logs over HTTP and syslog, and sends alerts. The module root is `/src`; `README.md` documents every feature and
`SECURITY-AUDIT.md` records earlier reviews and the risks that were accepted.

## What this project does and where untrusted input enters

SIEMLite exists to receive logs from other systems, which are attacker-influenced by nature, and show them to the
people defending those systems. **The contents of every log are untrusted**: an attacker who can make any monitored
system write a line can control what SIEMLite receives. The worst outcomes are an attacker who can (a) run code in or
crash SIEMLite, (b) read logs or data they should not see, (c) act as a user or an administrator, (d) hide or forge
events, or (e) attack a person's browser through log content shown in the UI.

Entry points, from least to most privileged caller:

1. **Syslog** (`pkg/syslogd`, flags `-syslog-udp`, `-syslog-tcp`, `-syslog-tls`). Off by default. There is no
   authentication, only a sender-IP allowlist (`-syslog-allow`, default loopback and private ranges). Messages up to
   64 KiB; the TCP side caps connections and idle time. The TLS listener does not ask for client certificates.
2. **Ingest API** with a send-only token (`Authorization: Bearer slk_...`): `POST /api/v1/events` (OCSF JSON) and
   `POST /api/v1/logs` (raw lines, or JSON objects). Bodies up to 16 MiB. A token can only send; it cannot search.
3. **Unauthenticated HTTPS routes**: `POST /api/v1/login`, `/logout`, `GET /api/v1/auth/providers`, the Microsoft Entra
   sign-in `GET /api/v1/auth/entra/start` and `/callback`, `GET /.well-known/siemlite-check/{nonce}`, `GET /health`
   (up/down only when anonymous), `GET /api/v1/me`, and the static UI.
4. **MCP endpoint** `POST /mcp`, for AI agents, with an agent token (`slmcp_...`) at read, analyst or admin level.
   Tool calls are dispatched in-process to the same REST handlers.
5. **Signed-in users** (session cookie `siemlite_session`): `admin` can do everything; `standard` can search, and may be
   limited to specific sources.
6. **The local port** (`-local-addr`, default `localhost:8444`), which treats a request as coming from the server
   itself and is used for the admin sign-in link and `siemlite signin`.

Also untrusted: the `q` search parameter (a raw SQLite FTS5 expression), query parameters on `/api/v1/search`, the
Entra `state` and `code` parameters, and anything in a restored backup file.

## Components that matter most / least

Most important:
- **Authentication, sessions and authorization**: `pkg/auth`, `api/server.go` (`Handler`, `Require`), `api/signin.go`,
  `api/mcp.go`, `pkg/agents`. A request must never get more than its token or session allows. Check every route,
  including those reached through MCP, for the permission it demands.
- **Data isolation**: a limited `standard` user must only ever see events from their allowed sources, in every API
  that returns event data, including search, stats, alerts, and anything reachable through MCP or by crafting the FTS5
  expression in `q`. Please try to bypass the source restriction (for example FTS5 column filters or other query
  syntax, alert rules, stats, pagination, or the MCP tools).
- **Ingest and parsing**: `api/server.go` (`handleIngest`, `handleLogs`), `pkg/parser`, `pkg/syslogd`, `pkg/ocsf`. These
  handle hostile input at volume and must not panic, hang, exhaust memory, or write outside their intended fields.
  Parsers are defined by admins (regexes, JSON and key=value formats) and run against attacker-controlled lines.
- **Rendering log content**: `web/static/index.html` and the response headers in `api/headers.go` (hash-based CSP).
  Log text must always be shown as text. Any way to make log content run script, or break out of the CSP, is high.
- **Storage and SQL**: `pkg/storage`. Queries should be parameterized; only integers the program chose are formatted
  into SQL. Look for any path where request data reaches SQL text.
- **Backup and restore**: `pkg/backup`, `api/system.go`. Archives are accepted only as regular files with fixed names;
  confirm no path traversal, symlink or overwrite is possible.
- **Secrets and sign-in**: `pkg/secret` (AES-256-GCM for the SMTP password, Entra secret and AI keys), `pkg/entra`
  (OIDC with PKCE, state, nonce), `pkg/certs`, password hashing and lockout in `pkg/auth/users.go`.

Less important, still in scope: the log generator `cmd/loggen`, threat-intel and GeoIP import, the alert engine
(`pkg/alerts`), email and the optional AI helper (`pkg/ai`, which talks to an admin-configured Ollama or OpenRouter),
and self-update (`pkg/update`).

Out of scope: the Go standard library and third-party modules (report a vulnerable dependency only if SIEMLite uses the
vulnerable code path), the distroless runtime image, and `e2e/` and `loadtest/`, which are test code.

## How to exercise it

The image has the checkout at `/src` and these binaries: `/src/bin/siemlite` (release build),
`/src/bin/siemlite-race` (same code built with the race detector; use it to look for data races), and
`/src/bin/loggen` (a test log generator). `curl`, `openssl`, `sqlite3`, `netcat` and `jq` are installed.

Start a server with a throwaway data folder (the audit has no network, so nothing here needs it):

```
mkdir -p /tmp/siem && cd /tmp/siem
/src/bin/siemlite -db /tmp/siem/siemlite.db -addr 127.0.0.1:8443 \
    -syslog-udp 127.0.0.1:5514 -syslog-tcp 127.0.0.1:5514 -update-check=false > server.log 2>&1 &
```

- It is HTTPS only, with a self-signed certificate (use `curl -k`). Every flag can also be set as
  `SIEMLITE_<FLAG_NAME>` (for example `SIEMLITE_ADDR`).
- On first start it creates an `admin` account and prints a random password to its output (here `server.log`). Create
  further accounts with `siemlite users create`, and send-only tokens with `siemlite keys create -name x`. Other
  subcommands: `siemlite version|healthcheck|users|keys|signin|backups|intel`.
- Sign in with `POST /api/v1/login` (`{"username":..., "password":...}`) and keep the `siemlite_session` cookie.
- The test suites run offline. `go test ./...` (add `-race` for the race detector); `scripts/security-check.sh` runs
  the tests named `TestSecurity*` in `./api ./pkg/auth ./web`, which cover the authorization rules and are a good
  place to see what is already guaranteed. Fuzz targets exist for the parsers (`pkg/parser`), the syslog framer
  (`pkg/syslogd`), backup names (`pkg/backup`) and threat-intel input (`pkg/intel`):
  `go test ./pkg/parser -run '^$' -fuzz FuzzParseLine -fuzztime 60s`.
- `README.md` lists every route, setting and role.

## How you rate severity

- **Critical**: remote code execution in the server; any way for an unauthenticated caller, or a send-only token, to
  read logs or reach admin functions; authentication bypass or session forgery; a standard user becoming admin.
- **High**: a limited user reading events from sources they are not allowed (data isolation bypass); a `standard` user
  or analyst-level agent reaching an admin-only function; stored cross-site scripting or CSP bypass from log content or
  any other stored field; SQL injection; reading or writing files outside the data and backup folders (path traversal);
  recovering secrets (the data folder's secret key, SMTP or Entra secrets, session tokens, password hashes) as a
  non-admin; a way to forge or delete events or alerts without ingest or admin rights.
- **Medium**: denial of service by an unauthenticated or send-only caller (a request that crashes the process,
  deadlocks it, or exhausts memory or disk with a small input); a cross-site request forgery that works against a
  signed-in user; weaknesses in sign-in throttling that allow practical password guessing; information disclosure of
  low-sensitivity data (versions, existence of usernames) to anonymous callers.
- **Low**: hardening gaps with no demonstrated exploit, missing headers, and denial of service that needs an admin or
  a very large input from a trusted network.
- Report only issues you can demonstrate against a running server or a test, with a reproducer. A theoretical issue
  without a working path is not a finding.

## Anything to leave alone

These are known and were accepted in `SECURITY-AUDIT.md`. Do not report them unless you find a way for a caller
*without* the privilege described to trigger them, or a way to make them worse than described:

- **Admins are trusted.** An admin can read all data and can make the server connect to hosts of their choosing
  (threat-intel feed URLs, SMTP host, Entra test, AI backend URL, the TLS reachability check), define parsers, and
  restore backups. Server-side request forgery, large uploads, or decompression bombs that need an admin session are
  accepted. Report them only if a non-admin can reach them.
- **Syslog has no authentication**, only a sender-IP allowlist, and the syslog TLS port does not use client
  certificates. Spoofed UDP senders are inherent to syslog.
- **No rate limit on ingest.** A send-only token or an allowed syslog sender can fill the queue and the disk; UDP
  drops events when the queue is full. Report a *crash* or hang from a small input, not volume.
- **The first admin password is printed once to standard output** (so it appears in `docker logs`).
- **Self-update** checks a downloaded binary against the `SHA256SUMS` of the same release only. A compromised release
  is out of scope.
- **A single event can be up to 16 MiB.**
- **The CSRF check allows requests that carry neither `Origin` nor `Sec-Fetch-Site`**, since non-browser clients send
  neither. Report a cross-site attack only if it works from a browser.
- The self-signed certificate is not trusted by clients; use `-k`.

## What a good report and patch look like

Include the exact request or command sequence, which account or token it needs, what the server did and what it
should have done. Patches should be small and match the surrounding style (`gofmt`, comments in plain language, tests
next to the code in `*_test.go`; authorization rules get a `TestSecurity...` test in the package that enforces
them), and `go vet ./... && go test ./...` must still pass.
