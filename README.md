# mitm-adblock

An ad-blocking addon for [mitmproxy](https://mitmproxy.org), powered by Brave's
[adblock-rust](https://github.com/brave/adblock-rust) engine.

- Network blocking with ABP/uBO-syntax lists, HTTP redirects, and HTML responses with explicit HTTP `Refresh` targets
- EasyList, EasyPrivacy,
  [HaGeZi Threat Intelligence Feeds Full](https://github.com/hagezi/dns-blocklists#tif),
  [HaGeZi Pop-Up Ads](https://github.com/hagezi/dns-blocklists#popupads),
  [OISD Big](https://oisd.nl/setup/adblockplus),
  [uBlock Origin Badware Risks](https://github.com/uBlockOrigin/uAssets/blob/master/filters/badware.txt),
  and [URLhaus Online](https://github.com/curbengh/urlhaus-filter) enabled by default
- Bundled [first-party rules](first-party.txt) for confirmed publisher-hosted ad endpoints
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

To run from a checkout, install the Rust toolchain used in the Dockerfile,
then build the Python extension:

```sh
pip install -r requirements.txt ./engine
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
| `adblock_lists` | EasyList, EasyPrivacy, HaGeZi TIF Full, HaGeZi Pop-Up Ads, OISD Big, uBlock Origin Badware Risks, URLhaus Online, bundled first-party rules | Comma-separated URLs and/or local paths |
| `adblock_cache_dir` | `~/.cache/mitm-adblock` | Where downloaded lists are cached |
| `adblock_update_hours` | `24` | How often lists are downloaded again |
| `adblock_cosmetic` | `true` | Inject element-hiding CSS |
| `adblock_log_blocked` | `false` | Log every blocked request |
| `adblock_threatfox_key_file` | empty | Optional path to an abuse.ch ThreatFox authentication key |
| `adblock_threat_domains_file` | empty | Optional file containing additional exact threat hostnames, one per line |

To allow a site, add a rule like `@@||example.com^$document` to your own rules file.
Setting `adblock_lists` replaces the defaults. The proxy forwards allowed URLs
with their original query parameters, including when a list contains `$removeparam` rules.

## ThreatFox

Mount a file containing the [ThreatFox authentication key](https://threatfox.abuse.ch/export/)
readable by the proxy user. Set `ADBLOCK_THREATFOX_KEY_FILE` to its path inside
the container or pass `--set adblock_threatfox_key_file=/path/to/key`.
The proxy adds reported dedicated C2 and payload-delivery domains with a
confidence of at least 75. Matching uses the named hostname, including the
optional final DNS dot. The proxy refreshes the export with its other lists
and can use a cached copy for up to seven days if the download fails.

## First-party ads and tracking

Network rules apply to matching requests on the publisher's own site, including
specific paths such as `||example.com/assets/ad.js^`. A cosmetic rule such
as `example.com##.sponsored-card` hides matching content inside the publisher's
HTML. Ads embedded in otherwise legitimate media or API responses require
format-specific filtering.

## Stress testing

Replay archived ad traffic and check reported malvertising indicators in an
offline gVisor sandbox. See the [stress testing runbook](stress/README.md) for
the disposable Proxmox VM setup, public starter corpus, and capture format.

Size the production container for list compilation and refresh as well as steady
traffic. The [measured memory requirements](stress/README.md#size-the-sandbox-for-the-workload)
include a rebuild while the previous engine is still resident. Existing
installations can use a cached TIF Medium snapshot when TIF Full and its cache
are unavailable.
