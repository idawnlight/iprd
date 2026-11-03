# iprd

`iprd` is a standalone iCloud Private Relay client and local proxy daemon written in Go.

On macOS and iOS, Private Relay is tied to system daemons and restricted to Safari and specific Apple traffic. `iprd` implements the protocol stack directly in pure Go (`CGO_ENABLED=0`), turning an iCloud+ subscription into a standard local proxy on any platform Go supports. It listens on a single port for SOCKS5 (`CONNECT` and `UDP ASSOCIATE`), HTTP `CONNECT`, and plain HTTP requests, forwarding traffic over two-hop QUIC/HTTP/3 (with automatic HTTP/2 TCP fallback).

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

List all relays and two-hop paths from Apple's public configuration (no account needed):

```sh
./bin/iprd debug --list
```

Prefer specific ingress or egress vendors/hostnames, or force `h3` / `h2` transport (defaults to `auto`, which prefers H3 and falls back to H2 for TCP):

```sh
./bin/iprd serve --egress Fastly,CloudFlare
./bin/iprd serve --transport h2 --ingress Apple --egress cp4.cloudflare.com
```

Run a one-shot probe through both hops without starting the proxy listener:

```sh
# TCP probe (defaults to H3 with H2 fallback; use --transport h2 or h3 to pin)
./bin/iprd debug --url https://api.ipify.org/
./bin/iprd debug --transport h2 --url https://api.ipify.org/

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
           [--anisette-server URL] [--token-pool-size N] [--transport auto|h3|h2]
           [--ingress PREF] [--egress PREF]
iprd debug [--list] [--json] [--url URL | --udp HOST:PORT] [--timeout DURATION]
           [--transport auto|h3|h2] [--account FILE | --subscription FILE]
           [--ingress PREF] [--egress PREF]
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

## Location and Geohash

Exit IP location in Private Relay is controlled at two separate layers: the country is determined by the token key in the signed configuration, and the city within that country is selected per stream by the `Sec-CH-Geohash` header.

### Country Selection (`fetchConfigFile` and `tokenKeyInfo`)

The public configuration endpoint (`https://mask-api.icloud.com/v6_2/fetchConfigFile`) requires no account credentials—only the `X-Mask-Client-Info` header—and returns a regional configuration based on the requester's IP (for example, `JP-JST` in Japan or `FI-EET` in Finland).

Each regional configuration assigns a region-specific RSA blind-signature public key (`tokenKeyInfo`) to every hop, even when the proxy hostname and TLS raw public keys are shared globally (such as `mask.icloud.com:443` and `cp4.cloudflare.com:443`). When the egress hop redeems a `PrivacyToken`, it determines the client's country and time zone from the token's 32-byte `keyID` (`SHA-256(tokenKeyInfo)`), not from which Apple ingress POP forwarded the connection.

Apple's token issuer (`/prod/v1/fetchAuthTokens`) does not check whether the client's source IP matches the region of the requested `tokenKeyInfo`. A client in Japan that loads a `FI-EET` configuration can issue valid Finnish tokens and receive Finnish exit IPs (`loc=FI`) across Cloudflare, Fastly, and Akamai—even while dialing through its local Japanese Apple ingress and local Tokyo Cloudflare POP (`colo=NRT`).

### City Selection (`Client-Geohash` and `Sec-CH-Geohash`)

When the Apple ingress hop responds `200 OK` to `CONNECT` or `CONNECT-UDP`, it returns `Client-Geohash: "xxxx"`, an RFC 8941 structured string containing a 4-character base32 geohash (~39 km × 19.5 km) derived from the client's source IP.

On the second hop, the client can attach `Sec-CH-Geohash: "xxxx"` to each egress `CONNECT` or `CONNECT-UDP` request to steer the exit IP to a city subnet from Apple's [egress geofeed](https://mask-api.icloud.com/egress-ip-ranges.csv). The header is evaluated per stream on an existing egress session without consuming additional tokens:

| Mode | Egress Header | Cloudflare | Fastly | Akamai |
| --- | --- | --- | --- | --- |
| Country and time zone (`iprd` default) | *(omitted)* | Default regional `/45` | Country-only `/40` or `/48` (no city tag) | Default POP `:4000::/64` |
| Maintain general location / override | `Sec-CH-Geohash: "xxxx"` | Matching city `/45` | Matching city `/52` | Matching city `:6xxx::/64` / `:exxx::/64` |
| Out-of-country geohash | `Sec-CH-Geohash: "xxxx"` | Clamped to nearest domestic border city | Falls back to country-only prefix | Falls back to default `:4000::/64` |

## Not Implemented Yet

- OHTTP and ODoH: `*_OHTTP`, `*_OHTTP_Relay`, and `Apple_DOH` entries in the signed configuration (and the `odoh` DNS weights table) are shown by `debug --list` but not used. DNS goes through SOCKS5 remote hostname resolution or standard UDP relay (`CONNECT-UDP`).
- Destination-based `preferredPathPatterns` and `fetchPreferredPath`: Egress vendors publish CIDR/domain matching rules and a `fetchPreferredPath` endpoint in the configuration to steer specific destinations to specific egress nodes. `iprd` uses static weight/preference selection across published paths.
- Geohash / location flags: `iprd` currently omits `Sec-CH-Geohash` on egress requests ("Use country and time zone"); see [Location and Geohash](#location-and-geohash).
- Hardware BAA attestation (`DeviceIdentity`): The configuration (`authType = 3`) accepts either hardware-backed BAA signatures or Anisette. For cross-platform portability, `iprd` only implements the Anisette branch.
