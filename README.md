# gotunnel

Secure TCP tunnel with ChaCha20 encryption and persistent connections.

Forked from [xjdrew/gotunnel](https://github.com/xjdrew/gotunnel) with modern security and Go optimizations.

## Architecture

```
client <-> gotunnel <--------------> gotunnel <-> server
         (encrypted, persistent tunnels)
```

## Features

- **ChaCha20 encryption** (upgraded from deprecated RC4)
- **SHA-256 authentication** (upgraded from MD5)
- **Cryptographically secure random** via `crypto/rand`
- **Persistent tunnel connections** — no per-request TCP handshake overhead
- **Multiplexed links** — multiple application connections over few tunnels
- **Heartbeat monitoring** with automatic reconnection and exponential backoff
- **Graceful shutdown** via SIGTERM/SIGINT

## Build

```bash
./build.sh
# or
go build -o bin/gotunnel .
```

For OpenWRT builds, see [docs/build_openwrt](docs/build_openwrt/).

## Usage

```
usage: bin/gotunnel
  -backend string     backend address (default "127.0.0.1:1234")
  -heartbeat int      tunnel heartbeat interval in seconds (default 10)
  -listen string      listen address (default ":8001")
  -log uint           log level (default 1)
  -secret string      tunnel secret
  -timeout int        tunnel read/write timeout in seconds (default 30)
  -tunnels uint       low-level tunnel count (0 = server mode)
```

**Server mode** (`-tunnels 0`): listens for tunnel connections, forwards to backend.
**Client mode** (`-tunnels > 0`): creates persistent tunnels to server, listens locally.

## Example

Server side (encrypt traffic to local squid):
```bash
./gotunnel -listen=:8001 -backend=127.0.0.1:3128 -secret="your secret"
```

Client side (local proxy with encryption):
```bash
./gotunnel -tunnels=100 -listen="127.0.0.1:8080" -backend="server:8001" -secret="your secret"
```

Then use `curl --proxy 127.0.0.1:8080 http://example.com` — all traffic is encrypted.

## Upgrades from Original

| Feature | Original | This Fork |
|---------|----------|-----------|
| Encryption | RC4 (deprecated) | ChaCha20 |
| Auth signature | MD5 | SHA-256 |
| Random source | `math/rand` | `crypto/rand` |
| Signal handling | SIGHUP only | SIGHUP + SIGTERM + SIGINT |
| Deprecated APIs | `net.Error.Temporary()` | `net.Error.Timeout()` |
| Go style | `interface{}` | `any` (Go 1.18+) |
| Panic messages | `"!!"` | descriptive error |
| Memory pool | strict `cap == sz` check | relaxed `cap >= sz` |

See [CHANGELOG.md](CHANGELOG.md) for details.

## License

MIT — Copyright (c) 2015 xjdrew, 2026 RaindyRoye
