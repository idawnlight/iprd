# iprd

`iprd` is a standalone iCloud Private Relay client and local proxy daemon written in Go.

On macOS and iOS, Private Relay is tied to system daemons and restricted to Safari and specific Apple traffic. `iprd` implements the protocol stack directly in pure Go (`CGO_ENABLED=0`), turning an iCloud+ subscription into a standard local proxy on any platform Go supports. It listens on a single port for SOCKS5 (`CONNECT` and `UDP ASSOCIATE`), HTTP `CONNECT`, and plain HTTP requests, forwarding TCP over two-hop HTTP/2 and UDP over two-hop QUIC/HTTP/3.

## Usage

Requires Go 1.26+ and an Apple Account with iCloud+.

```sh
go build -o bin/iprd ./cmd/iprd
```

Authenticate once to provision an Anisette v3 identity (`runtime/anisette/`) and save MobileMe credentials (`runtime/account.json`):

```sh
./bin/iprd auth
```

Start the proxy (defaults to `0.0.0.0:1080`):

```sh
./bin/iprd serve --listen 127.0.0.1:1080
```

In another terminal:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org/
curl --proxy http://127.0.0.1:1080 https://api.ipify.org/
curl --proxy http://127.0.0.1:1080 http://example.com/
```

`serve` refreshes the CSF subscription, verifies Apple's signed relay configuration, and maintains an in-memory pool of blind-signed tokens for each hop. Active configurations and proxy tokens stay in memory and are never written to disk.

## Route Selection and Debugging

List all relays and two-hop fallback paths from Apple's public configuration (no account needed):

```sh
./bin/iprd debug --list
```

Prefer specific ingress or egress vendors/hostnames on `serve` or `debug`:

```sh
./bin/iprd serve --egress Fastly,CloudFlare
./bin/iprd serve --ingress Apple --egress cp4.cloudflare.com
```

Run a one-shot probe through both hops without starting the proxy listener:

```sh
# TCP probe
./bin/iprd debug --url https://api.ipify.org/

# UDP DNS probe over two-hop QUIC / HTTP/3
./bin/iprd debug --udp 1.1.1.1:53 --egress Fastly

# JSON output
./bin/iprd debug --json
```

## Flags

```text
iprd auth  [--anisette-state DIR] [--anisette-server URL] [--output FILE] [--init-only] [--debug-dir DIR]
iprd csf   [--account FILE] [--output FILE]
iprd serve [--listen ADDR] [--account FILE | --subscription FILE] [--anisette-state DIR]
           [--anisette-server URL] [--token-pool-size N] [--ingress PREF] [--egress PREF]
iprd debug [--list] [--json] [--url URL | --udp HOST:PORT] [--timeout DURATION]
           [--account FILE | --subscription FILE] [--ingress PREF] [--egress PREF]
```

By default, credentials are read from `runtime/account.json`, Anisette state from `runtime/anisette`, and Anisette headers from `https://new.ani.sidestore.io`. `--token-pool-size` defaults to 60 tokens per hop (refilling at 30).

Apple's GrandSlam login (`iprd auth`) [currently rejects](https://github.com/SideStore/SideStore/issues/1709) Android-based `CoreADI` providers (`-80045`), whereas `https://new.ani.sidestore.io` succeeds. Once `runtime/account.json` is created, however, Private Relay token issuance (`iprd serve` and `iprd debug`) works with standard self-hosted Android `CoreADI` v3 servers (e.g., [`anisette-v3-server`](https://github.com/Dadoum/anisette-v3-server)). To avoid load on public Anisette instances during normal operation, run `auth` once against the default server, then point `serve` at a local v3 server with its own state directory:

```sh
./bin/iprd serve --anisette-server http://127.0.0.1:6969 --anisette-state runtime/anisette-local
```

## Internals

- `internal/auth` — Anisette v3 provisioning, GrandSlam SRP-6a (`s2k` / `s2k_fo`), 2FA, MobileMe login, and CSF token exchange.
- `internal/control` — Protobuf configuration parser, Apple `networkserviceproxy` certificate chain and ECDSA signature verification, `RSABSSA-SHA384-PSS-Deterministic` token blinding, and token pool management.
- `internal/relay` — Single-hop HTTP/2 (TCP) and QUIC/HTTP/3 (UDP) clients composed recursively (egress dials through ingress).
- `internal/proxy` — Mixed SOCKS5 and HTTP listener.
- `internal/diagnostic` — Stage reporter for `iprd debug`.

Private Relay servers present bare SPKIs during TLS 1.3 handshakes via RFC 7250 (`server_certificate_type = 2`) instead of X.509 certificates. Since standard `crypto/tls` does not support RFC 7250, `go.mod` points to [`github.com/idawnlight/quic-go`](https://github.com/idawnlight/quic-go/tree/iprd-rpk), which adds raw public key support for both TLS 1.3 and QUIC.

```sh
go vet ./...
go test -race ./...
```
