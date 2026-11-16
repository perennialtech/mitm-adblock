# mitm-adblock

An ad-blocking addon for [mitmproxy](https://mitmproxy.org), powered by Brave's
[adblock-rust](https://github.com/brave/adblock-rust) engine.

- Network blocking with ABP/uBO-syntax lists (EasyList + EasyPrivacy by default)
- Cosmetic filtering: element-hiding CSS injected into HTML, with CSP nonces handled
- Lists cached in `~/.cache/mitm-adblock` and refreshed every 24 hours

## Usage

Run the [container image](https://github.com/perennialtech/mitm-adblock/pkgs/container/mitm-adblock)
on Linux x86-64. For a private GHCR package, sign in to `ghcr.io` with an
account that has package read access before running:

```sh
docker run --rm -p 127.0.0.1:8080:8080 \
  -v mitm-adblock-ca:/var/lib/mitmproxy \
  ghcr.io/perennialtech/mitm-adblock:latest
```

The volume keeps the proxy's CA across restarts. Keep its private key on
the proxy host. To share the proxy with trusted LAN or VPN clients,
replace `127.0.0.1` in the port mapping with the host's LAN address and
restrict access to that network.

To run from a checkout instead:

```sh
pip install -r requirements.txt
mitmdump -s adblock_addon.py
```

Point your browser or system proxy at the proxy host and port, then open
http://mitm.it through the proxy to install the CA for HTTPS filtering.

To run mitmproxy as its own WireGuard server, start it with
`mitmweb --mode wireguard -s adblock_addon.py` and import the configuration
shown in the web interface.

## Options (`--set name=value`)

| Option | Default | Meaning |
|---|---|---|
| `adblock_lists` | EasyList, EasyPrivacy | Comma-separated URLs and/or local paths |
| `adblock_cache_dir` | `~/.cache/mitm-adblock` | Where downloaded lists are cached |
| `adblock_update_hours` | `24` | How often lists are downloaded again |
| `adblock_cosmetic` | `true` | Inject element-hiding CSS |
| `adblock_log_blocked` | `false` | Log every blocked request |

To allow a site, add a rule like `@@||example.com^$document` to your own rules file.
