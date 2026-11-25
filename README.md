# PCS · Proxy Chain Server

A small, fast SOCKS5 server that forwards every connection through a **chain of upstream SOCKS5 proxies**. Point any SOCKS5-capable application at PCS and its traffic leaves through proxy 1, then proxy 2, then proxy 3, and finally reaches the target.

Written in Rust with [tokio](https://tokio.rs). No other dependencies.

```
                     ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
 your app ─SOCKS5──▶ │   PCS   │──▶ │ proxy #1 │──▶ │ proxy #2 │──▶ │ proxy #3 │──▶ target
                     └─────────┘    └──────────┘    └──────────┘    └──────────┘
                      127.0.0.1:1080
```

## Features

- **Any chain length.** One proxy or ten, mixed authenticated and unauthenticated hops.
- **Remote DNS.** Domain names are passed down the chain untouched, so only the last proxy resolves them.
- **IPv4, IPv6 and domain targets**, for both clients and upstream proxies.
- **Optional client authentication** (RFC 1929 username/password) so you can safely listen beyond localhost.
- **Accurate failures.** If a hop refuses or times out, the client gets the matching SOCKS5 reply code (connection refused, host unreachable, ...) instead of a generic error.
- **Hardened by default:** timeouts on the client handshake and on every step of building the chain, and a cap on concurrent chain builds.
- **Readable logs.** Colored, timestamped output with per-connection IDs, per-hop timing and traffic totals. Colors switch off automatically when output is piped or `NO_COLOR` is set.

## Build

You need a recent stable Rust toolchain ([rustup.rs](https://rustup.rs)).

```sh
git clone https://github.com/s0ck37/pcs.git
cd pcs
cargo build --release
```

The binary ends up in `target/release/`.

If you are setting the project up from scratch, `Cargo.toml` only needs tokio:

```toml
[package]
name = "pcs"
version = "1.0.0"
edition = "2024"

[dependencies]
tokio = { version = "1", features = ["full"] }
```

The sources are `src/main.rs` (server) and `src/lib_client.rs` (the SOCKS5 client used to talk to the upstream proxies).

## Configuration

PCS reads a plain-text config file, `config.conf` in the current directory unless you pass another path. Blank lines and lines starting with `#` are ignored.

```ini
# address PCS listens on
bind = 127.0.0.1:1080

# optional: require clients to log in (username:password)
# auth = alice:s3cret

# upstream proxies, in order. The first one is contacted directly,
# each following one is reached through the previous.
proxy = 203.0.113.10:1080
proxy = bob:hunter2@198.51.100.7:1080
proxy = [2001:db8::1]:1080
```

| Key     | Required | Description |
|---------|----------|-------------|
| `bind`  | yes      | Listen address, `ip:port`. IPv6 uses brackets: `[::1]:1080`. |
| `proxy` | yes, one or more | `host:port` or `user:pass@host:port`. Order matters: first line is the first hop. Hosts can be IPs or domain names. |
| `auth`  | no       | `user:pass`. When set, clients must authenticate with username/password. When absent, PCS accepts unauthenticated clients. |

Usernames and passwords are limited to 255 bytes each, as required by the protocol.

## Usage

```sh
pcs                      # uses ./config.conf
pcs /etc/pcs/chain.conf  # custom config
pcs --quiet              # only warnings and errors after startup
pcs --help
```

Then use it like any SOCKS5 proxy:

```sh
# curl (socks5h = let the proxy resolve the hostname)
curl --proxy socks5h://127.0.0.1:1080 https://example.com

# with client auth enabled
curl --proxy socks5h://alice:s3cret@127.0.0.1:1080 https://example.com

# ssh
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@host

# git
git config --global http.proxy socks5h://127.0.0.1:1080
```

Press `Ctrl-C` to stop. PCS prints a summary of connections served and bytes transferred.

## Example output

```
╭─────────────────────────────────────╮
│  PCS · Proxy Chain Server · v0.1.0  │
╰─────────────────────────────────────╯

  config   config.conf
  listen   127.0.0.1:1080
  clients  no authentication
  limits   10.00s timeout · 64 concurrent chain builds
  mode     verbose
  chain    you
           ├─ 1  203.0.113.10:1080
           ├─ 2  198.51.100.7:1080 [auth]
           └─ target

12:04:31.220 INFO        ● ready, waiting for connections (Ctrl-C to stop)
12:04:35.871 INFO  #0001 ↘ accepted 127.0.0.1:51734  active 1
12:04:35.872 INFO  #0001 CONNECT example.com:443  handshake 1ms
12:04:35.934 DEBUG #0001 connected to first proxy 203.0.113.10:1080 (203.0.113.10) in 61ms
12:04:36.011 DEBUG #0001 hop 1/2  203.0.113.10:1080 → 198.51.100.7:1080  (77ms)
12:04:36.140 DEBUG #0001 hop 2/2  198.51.100.7:1080 [auth] → example.com:443  (129ms)
12:04:36.140 OK    #0001 ✔ tunnel to example.com:443 established via 2 hops in 268ms
12:04:38.502 INFO  #0001 ■ closed example.com:443  ↑ 1.2 KiB  ↓ 48.6 KiB  · 2.36s
```

When something goes wrong the log says exactly where:

```
12:07:02.418 ERROR #0007 ✖ chain to example.com:443 failed at hop 2/2: external proxy server: connection refused
```

## How it works

1. A client connects and speaks SOCKS5 to PCS (CONNECT only).
2. PCS opens **one** TCP connection to the first proxy.
3. Over that same connection it asks proxy 1 to CONNECT to proxy 2, then asks proxy 2 to CONNECT to proxy 3, and so on. The last request asks the final proxy to connect to the real target.
4. PCS tells the client the tunnel is ready and then relays bytes in both directions until either side closes.

## Limitations

- Only the **CONNECT** command is supported. UDP ASSOCIATE and BIND are answered with "command not supported".
- Upstream proxies must be SOCKS5. Supported upstream auth: none or username/password. GSSAPI is not supported.
- The hostname of the *first* proxy is resolved locally by PCS; everything after that is resolved remotely.
- Traffic between hops is only as private as the proxies themselves. A chain does not add encryption: wrap your own traffic in TLS/SSH if you need that.

## Security notes

- By default PCS accepts **unauthenticated** clients. That is fine on `127.0.0.1`. If you bind to anything else, set `auth = user:pass` or firewall the port, otherwise you are running an open relay into your chain. PCS prints a warning at startup when it detects this.
- Client credentials are compared in constant time, but they travel in clear text over the SOCKS5 connection (that is how RFC 1929 works). Do not expose the listener to untrusted networks without a tunnel.
- Credentials in the config file are never written to the logs, hops only show an `[auth]` marker. Keep the file readable only by the user running PCS (`chmod 600 config.conf`).

## Contributing

Issues and pull requests are welcome at [github.com/s0ck37/pcs](https://github.com/s0ck37/pcs).
