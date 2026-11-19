# mitm-adblock

A Rust ad-blocking proxy for enrolled browsers and apps. It uses Brave’s adblock engine for network and cosmetic rules, handles HTTP/1.1, HTTP/2 and HTTP/3, and can remove Safari Smart App Banners. The production container runs the native executable.

## Run with Docker

From a checkout, run `docker compose -f examples/compose.yaml up -d --build`. Configure your browser’s HTTP and HTTPS proxy settings with the loopback address in the Compose file. Open `http://mitm.it/` through the proxy to download its public CA, then install and trust the certificate on the enrolled device. To use the prebuilt Linux x86-64 image, set `MITM_ADBLOCK_IMAGE` to a [published image](https://github.com/perennialtech/mitm-adblock/pkgs/container/mitm-adblock) and use `up -d --pull always --no-build`.

The existing CA volume, `mitmproxy-ca.pem`, public CA certificate, filter cache names and ThreatFox snapshots work with the Rust executable. Keep the private CA volume on the proxy host. The default Compose port binds to loopback. For enrolled LAN devices, bind it to the LAN interface and restrict access to those devices.

## Configure filtering and routing

Run `docker compose -f examples/compose.yaml run --rm proxy --options` to see the native command-line options and default subscriptions. Use repeated `--set name=value` arguments in the Compose service’s `command`. File paths refer to files mounted in the container. For example, `--set adblock_lists=/filters/local.txt` replaces the default lists. Prefix a secondary list with `supplement:` to preserve primary blocks and exceptions. Filter updates build in the background while requests continue with the current rules.

The default `tls_fallback_mode=compatible` lets a client that rejected the proxy certificate retry with the origin certificate. That connection passes through unfiltered. `strict` limits automatic fallback to selected TCP certificate alerts. `off` disables it. The proxy verifies origin certificates for intercepted HTTPS requests. Use `ssl_verify_upstream_trusted_ca` to supply a private trust bundle.

| Mode | How to use it |
| --- | --- |
| Explicit HTTP proxy | Use the default `--mode regular`. HTTPS clients connect using HTTP CONNECT. |
| Transparent TCP on Linux | Use `--mode transparent --listen-port 8083` with your existing TCP redirect and original-destination routing. |
| Routed TCP and HTTP/3 on Linux | Use `--mode tun:mitm-h3`. Give the container its own network namespace, `/dev/net/tun`, and permission to administer that interface. Route the enrolled IPv4/IPv6 traffic to it. |
| WireGuard on Linux | Use `--mode wireguard` and publish UDP 51820 to the enrolled client. The default mode creates or reuses `wireguard.conf` in the CA directory. |
| HTTP/3 reverse listener | For a fixed HTTP/3 origin, use `--mode reverse:http3://origin.example:443@127.0.0.1:8443`. |

HTTP/3 uses QUIC v1. Clients that offer v1 can negotiate it after a version probe. A v2-only peer requires [QUIC v2 support in Quinn](https://github.com/quinn-rs/quinn/issues/2740).

Repeat `--mode` for multiple listeners. For WireGuard, run the following in a private directory and import the resulting client profile. Replace the example endpoint with the address reachable by the enrolled device. The command reads the same persistent volume used by the proxy.

```sh
umask 077
docker compose -f examples/compose.yaml run --rm proxy \
    --wireguard-profile proxy.example:51820 > client.conf
```

When migrating an existing deployment, replace its `mitmdump` invocation with `mitm-adblock` and remove Python `-s` addon arguments. The enrollment command replaces the interactive WireGuard profile page. Native options are listed by `--options`.

## Build and test

Use Rust 1.99 or newer. On Debian, install `pkg-config libssl-dev libcurl4-openssl-dev libzstd-dev`. From the repository root:

```sh
cargo build --locked --bin mitm-adblock
cargo run --locked -- --help
cargo test --locked --workspace
```

Use `cargo test -p mitm-adblock-policy` when editing filters. The policy and subscriptions are separate crates. Development builds keep line tables and use Cargo’s incremental cache. Docker caches the compiled release dependencies separately from application source. The build uses ring for Rustls, distro libraries for OpenSSL, curl and Zstandard, and the Brotli decoder for response bodies.

Run `./scripts/check-image` for the publish gate. It tests the Rust workspace, exercises the production binary against loopback TCP and HTTP/3 origins, and starts the final image through its normal entrypoint. The separate Docker `replay` target includes the Python tooling for archived browsing sessions. See [the replay instructions](AGENTS.md) for the isolated publisher-capture and browser tests.
