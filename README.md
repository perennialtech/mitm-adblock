# mitm-adblock

An ad-blocking addon for [mitmproxy](https://mitmproxy.org), powered by Brave's
[adblock-rust](https://github.com/brave/adblock-rust) engine.

- Network blocking with ABP/uBO-syntax lists (EasyList + EasyPrivacy by default)
- Cosmetic filtering: element-hiding CSS injected into HTML, with CSP nonces handled
- Lists cached in `~/.cache/mitm-adblock` and refreshed every 24 hours

## Usage

    pip install -r requirements.txt
    mitmdump -s adblock_addon.py

Point your browser or system proxy at `127.0.0.1:8080`, then install the CA
from http://mitm.it (open it through the proxy).

For phones: `mitmdump --mode wireguard -s adblock_addon.py`, then scan the QR code.

## Options (`--set name=value`)

| Option | Default | Meaning |
|---|---|---|
| `adblock_lists` | EasyList, EasyPrivacy | Comma-separated URLs and/or local paths |
| `adblock_cache_dir` | `~/.cache/mitm-adblock` | Where downloaded lists are cached |
| `adblock_update_hours` | `24` | How often lists are downloaded again |
| `adblock_cosmetic` | `true` | Inject element-hiding CSS |
| `adblock_log_blocked` | `false` | Log every blocked request |

To allow a site, add a rule like `@@||example.com^$document` to your own rules file.
