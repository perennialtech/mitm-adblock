# syntax=docker/dockerfile:1
FROM rust:1.99-bookworm AS dependencies
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/policy/Cargo.toml crates/policy/
COPY crates/subscriptions/Cargo.toml crates/subscriptions/
# This layer only changes when manifests, the lockfile or the toolchain change.
# Discard the three empty local packages before overlaying the real sources.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    mkdir -p src crates/policy/src crates/subscriptions/src \
    && echo 'fn main() {}' > src/main.rs \
    && touch crates/policy/src/lib.rs crates/subscriptions/src/lib.rs \
    && cargo build --locked --release --bin mitm-adblock \
    && cargo clean --release -p mitm-adblock -p mitm-adblock-policy -p mitm-adblock-subscriptions

FROM dependencies AS build
COPY crates/ crates/
COPY src/ src/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --locked --release --bin mitm-adblock

FROM build AS rust-tests
COPY tests/*.rs tests/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo test --locked --release --workspace && cargo build --locked --release --bin replay-policy

FROM python:3.13-slim-bookworm AS test-tools
RUN apt-get update && apt-get install -y --no-install-recommends libcurl4 libzstd1 openssl iproute2 iptables \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --only-binary=:all: 'mitmproxy>=11'

FROM test-tools AS replay
COPY --from=rust-tests /build/target/release/replay-policy /usr/local/bin/replay-policy
USER 10001:10001

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/perennialtech/mitm-adblock"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 libcurl4 libzstd1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 mitmproxy \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/mitmproxy --no-create-home mitmproxy \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/mitmproxy /var/cache/mitm-adblock
COPY --from=build /build/target/release/mitm-adblock /usr/local/bin/mitm-adblock
ENV HOME=/var/lib/mitmproxy MITM_ADBLOCK_CONFDIR=/var/lib/mitmproxy MITM_ADBLOCK_CACHE=/var/cache/mitm-adblock MITM_ADBLOCK_BIND=0.0.0.0
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["mitm-adblock"]
