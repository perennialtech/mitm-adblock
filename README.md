# mitm-adblock

An addon for [mitmproxy](https://mitmproxy.org) focused on intrusive advertising
and everyday browsing annoyances. The project prioritizes first-party and
third-party ads, pop-ups and pop-unders, ad redirects, and page clutter while
keeping legitimate content and site features usable. It uses Brave's
[adblock-rust](https://github.com/brave/adblock-rust) engine.

- Network blocking with ABP/uBO-syntax lists, HTTP redirects, and HTML responses with explicit HTTP `Refresh` targets
- Cosmetic filtering of matched overlays, sponsored cards, and leftover ad placements
- Removal of Safari Smart App Banner metadata from top-level pages
- EasyList, EasyPrivacy,
  [AdGuard Base supplement](https://github.com/AdguardTeam/AdGuardFilters) (the upstream edition without bundled EasyList),
  [Fanboy's Annoyance List](https://easylist.to/#fanboys-annoyance-list),
  [HaGeZi Threat Intelligence Feeds Full](https://github.com/hagezi/dns-blocklists#tif),
  [HaGeZi Pop-Up Ads](https://github.com/hagezi/dns-blocklists#popupads),
  [OISD Big](https://oisd.nl/setup/adblockplus),
  [Peter Lowe’s Ad and Tracking Server List](https://pgl.yoyo.org/adservers/),
  [uBlock Origin Badware Risks](https://github.com/uBlockOrigin/uAssets/blob/master/filters/badware.txt),
  and [URLhaus Online](https://github.com/curbengh/urlhaus-filter) enabled by default
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
| `adblock_lists` | EasyList, EasyPrivacy, AdGuard Base supplement, Fanboy’s Annoyance List, HaGeZi TIF Full, HaGeZi Pop-Up Ads, OISD Big, Peter Lowe’s Ad and Tracking Server List, uBlock Origin Badware Risks, URLhaus Online | Comma-separated URLs and/or local paths |
| `adblock_cache_dir` | `~/.cache/mitm-adblock` | Where downloaded lists are cached |
| `adblock_update_hours` | `24` | How often lists are downloaded again |
| `adblock_cosmetic` | `true` | Inject element-hiding CSS |
| `adblock_smart_app_banners` | `true` | Remove Safari Smart App Banner metadata |
| `tls_fallback_mode` | `compatible` | Recover from certificate rejections on TCP and HTTP/3. Also accepts `strict` or `off`. |
| `adblock_log_blocked` | `false` | Log every blocked request |
| `adblock_threatfox_key_file` | empty | Optional path to an abuse.ch ThreatFox authentication key |
| `adblock_threat_domains_file` | empty | Optional file containing additional exact threat hostnames, one per line |

Setting `adblock_lists` replaces the defaults. The proxy forwards allowed URLs
with their original query parameters, including when a list contains `$removeparam` rules.
The default AdGuard Base subscription uses the `supplement:` prefix. A
supplement adds coverage after the primary lists' blocks and exceptions. Its
exceptions and `$badfilter` rules apply within the supplement.
The default subscriptions block dedicated affiliate redirect hosts listed by
Peter Lowe, including direct visits to those redirect hosts.

## Clients that reject the proxy certificate

The ad blocker automatically helps apps that reject the proxy certificate. The
first handshake fails. For the next 120 seconds, a fresh TCP or HTTP/3
connection from the same client IP to the same destination and SNI hostname
on port 443 can connect through an encrypted tunnel. The app receives the
origin certificate and checks it normally. Ad blocking skips that tunnel.

| Setting | Behavior |
|---|---|
| `compatible` (default) | A certificate-stage rejection on either transport allows retries on either transport. This includes a client reporting a bad certificate or an unknown CA. |
| `strict` | Only a fatal TCP `certificate_unknown` or `access_denied` alert enables a TCP retry. HTTP/3 continues through filtering. |
| `off` | Disables automatic fallback. Explicit mitmproxy `ignore_hosts` rules still apply. |

Use `--set tls_fallback_mode=strict` to harden the proxy, or
`--set tls_fallback_mode=off` to require explicit exceptions.

The window controls when a tunnel can start. An established tunnel lasts
until the connection closes. Other apps on the same device can use the
window for that endpoint. While a relayed UDP flow is alive, connections
using the same client IP and source port to the same server also skip filtering.
This includes another hostname or a new socket that reuses that port, even
after the original QUIC connection closes or the two-minute window expires.
Each proxy process remembers up to 1,024 routes in memory. Cross-transport
retries share a window only when both reach the same process.

A silent disconnect, a missing SNI or a known upstream TLS failure does not
open a window. For an app that silently abandons a connection after checking
its pin, use a narrowly scoped `ignore_hosts` rule. Learning TCP rejections
requires pyOpenSSL 25.2 or newer.

If you previously loaded the standalone `tls-rejection-fallback.py`, remove its
`-s` argument when upgrading. While that script is configured it continues to
own fallback. The built-in policy takes over when you remove it.

## ThreatFox

Threat reputation lists provide supplemental protection. To enable ThreatFox,
mount a file containing the [ThreatFox authentication key](https://threatfox.abuse.ch/export/)
readable by the proxy user. Set `ADBLOCK_THREATFOX_KEY_FILE` to its path inside
the container or pass `--set adblock_threatfox_key_file=/path/to/key`.
The proxy adds reported dedicated C2 and payload-delivery domains with a
confidence of at least 75. Matching uses the named hostname, including the
optional final DNS dot. It also blocks exact HTTP and HTTPS payload URLs with
the same minimum confidence for seven days after they were last reported.
This protects individual paths on shared or compromised hosts and preserves
the original URL on allowed requests. The proxy refreshes the export with its
other lists and can use a cached copy for up to seven days if the download fails.

## First-party ads and tracking

Maintained lists cover publisher-hosted ads through request paths and
cosmetic selectors on the publisher's own page. Ads embedded in otherwise
legitimate media or API responses require format-specific filtering.

The proxy authorizes its exact stylesheet through HTTP Content-Security-Policy
headers and leaves author scripts and inline style attributes under the site's
policy. HTML with a CSP meta tag retains its original CSS policy. Pages served
as downloads or with `Cache-Control: no-transform` retain their body.

Filter decisions use HTTP context. The proxy can block a pop-up's known ad
destination or a dedicated script that opens it. Browser-side APIs are needed
to identify which tab opened a window, handle push permission prompts, and run
procedural cosmetic filters or scriptlets. Hiding a consent notice has no effect
on the user's consent decision.

## Stress testing

Replay real browsing captures in an offline gVisor sandbox. Prioritize ads,
redirects, and cosmetic rules alongside checks that legitimate requests still
work. See the [stress testing runbook](stress/README.md) for the disposable
Proxmox VM setup, public starter corpus, and optional historical campaign probes.

Size the production container for list compilation and refresh as well as steady
traffic. The [measured memory requirements](stress/README.md#size-the-sandbox-for-the-workload)
include a rebuild while the previous engine is still resident. Existing
installations can use a cached TIF Medium snapshot when TIF Full and its cache
are unavailable.
