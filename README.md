# mitm-adblock

An ad-blocking proxy for browsers and apps, built on [mitmproxy](https://mitmproxy.org/).

## Run with Docker

From a checkout, run `docker compose -f examples/compose.yaml up -d --build`.
Set your browser’s HTTP and HTTPS proxy to the loopback address in the
[Compose file](examples/compose.yaml). Open [mitm.it](http://mitm.it/) through
the proxy and follow the instructions to install and trust its certificate
authority. Keep the CA volume across restarts and its private key on the proxy host.
To serve trusted LAN clients, bind the port to the host’s LAN address and
restrict access to that network.

To use a prebuilt image on Linux x86-64, set `MITM_ADBLOCK_IMAGE` to a full image name and tag
from the [container registry](https://github.com/perennialtech/mitm-adblock/pkgs/container/mitm-adblock),
then run `docker compose -f examples/compose.yaml up -d --pull always --no-build`.

## Configure filtering

Run `docker compose -f examples/compose.yaml run --rm proxy --options` for the
option reference. The [image entrypoint](Dockerfile) sets container-specific
values, including the filter cache location. Search the option reference for `adblock_` to
change filter lists, cosmetic filtering or logging, and for `tls_fallback_mode`
to choose how the proxy handles apps that reject its certificate. Set options
in the Compose service’s `command` and run `docker compose -f examples/compose.yaml up -d`
to apply them. Mount any local filter lists or [ThreatFox key](https://threatfox.abuse.ch/export/)
where the container user can read them.

## Run without Docker

With Python and the [Rust toolchain used by the image](Dockerfile), activate a
Python virtual environment and run `python -m pip install -r requirements.txt ./engine`
from the checkout. Start the proxy with `mitmdump -s adblock_addon.py`,
or add `--options` to print the option reference.
For WireGuard clients, start `mitmweb --mode wireguard -s adblock_addon.py`
and import the client configuration from its web interface.
