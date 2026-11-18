#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# > 1 )); then
    printf 'Usage: %s [new corpus directory]\n' "$0" >&2
    exit 2
fi
destination=${1:-stress-corpus}
here=$(cd -- "$(dirname -- "$0")" && pwd)
stage=$(mktemp -d -- "$(dirname -- "$destination")/.stress-corpus.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT

download() {
    curl -q --fail --silent --show-error --proto '=https' \
        --max-time 60 --max-filesize "$3" --output "$stage/$2" "$1"
}

download https://easylist.to/easylist/easylist.txt easylist.txt 8388608
download https://easylist.to/easylist/easyprivacy.txt easyprivacy.txt 8388608
download https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt tif-medium.txt 16777216
download https://big.oisd.nl/ oisd-big.txt 16777216
download https://gvrkiran.github.io/adblock/nytimes.com.json nytimes.har 33554432
download https://humanprod.wpenginepowered.com/wp-content/uploads/4-26-Pushpaganda-Domain-list.csv pushpaganda.csv 1048576
(
    cd -- "$stage"
    sha256sum --strict --check <<'SUMS'
96654a49e4b073f322e213c5806b9770f7b9dfdac7c825e71bd9669f1cb22530  nytimes.har
c3fdfa2c133e57ca97cf0fff835b7f3ed114539ac3801a53c9fde2250233727d  pushpaganda.csv
SUMS
)
cp -- "$here/nytimes.labels.json" "$stage/"
cp -- "$here/../first-party.txt" "$stage/"
mv -T --no-clobber -- "$stage" "$destination"
if [[ -d "$stage" ]]; then
    printf 'Corpus destination already exists. Choose a new directory.\n' >&2
    exit 2
fi
