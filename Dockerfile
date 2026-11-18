FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/perennialtech/mitm-adblock"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
    && groupadd --gid 10001 mitmproxy \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/mitmproxy --no-create-home mitmproxy \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/mitmproxy /var/cache/mitm-adblock
COPY adblock_addon.py first-party.txt ./

ENV HOME=/var/lib/mitmproxy PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["mitmdump", "--mode", "regular", "--listen-host", "0.0.0.0", "--listen-port", "8080", "--set", "confdir=/var/lib/mitmproxy", "--set", "adblock_cache_dir=/var/cache/mitm-adblock", "--set", "flow_detail=0", "-s", "/app/adblock_addon.py"]
