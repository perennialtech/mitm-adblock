#!/usr/bin/env bash
set -euo pipefail
umask 077

with_campaigns=false
with_ranked_scans=false
while (( $# )); do
    case "$1" in
        --with-campaigns) with_campaigns=true ;;
        --with-ranked-scans) with_ranked_scans=true ;;
        *) break ;;
    esac
    shift
done
if (( $# > 1 )) || [[ ${1:-} == -* ]]; then
    printf 'Usage: %s [--with-campaigns] [--with-ranked-scans] [new corpus directory]\n' "$0" >&2
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
download https://secure.fanboy.co.nz/fanboy-annoyance.txt annoyances.txt 8388608
download https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt tif-full.txt 67108864
download https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt popupads.txt 4194304
download https://big.oisd.nl/ oisd-big.txt 16777216
download "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext" peter-lowe.txt 1048576
download https://ublockorigin.github.io/uAssets/filters/badware.txt badware.txt 1048576
download https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-online.txt urlhaus-online.txt 33554432
download https://gvrkiran.github.io/adblock/nytimes.com.json nytimes.har 33554432
(
    cd -- "$stage"
    sha256sum --strict --check <<'SUMS'
96654a49e4b073f322e213c5806b9770f7b9dfdac7c825e71bd9669f1cb22530  nytimes.har
SUMS
)
# Common Crawl, October 2026. Fetch only the archived PC Gamer response record.
warc_path=crawl-data/CC-MAIN-2026-43/segments/1791170054112.6/warc/CC-MAIN-20261006173032-20261006203032-00126.warc.gz
curl -q --fail --silent --show-error --proto '=https' --max-time 60 \
    --range 820300279-820697935 --max-filesize 397657 \
    --output "$stage/pcgamer.warc.gz" "https://data.commoncrawl.org/$warc_path"
(
    cd -- "$stage"
    sha256sum --strict --check <<'SUMS'
07e594e01cba279ca40cf5c35bbab6feebdec1155acfb7df0b30c0e7e1f19fbd  pcgamer.warc.gz
SUMS
)
python3 "$here/import-publisher.py" "$stage/pcgamer.warc.gz" "$stage/pcgamer.har"
rm -- "$stage/pcgamer.warc.gz"

if [[ $with_campaigns == true ]]; then
    download https://humanprod.wpenginepowered.com/wp-content/uploads/4-26-Pushpaganda-Domain-list.csv pushpaganda.csv 1048576
    download https://humanprod.wpenginepowered.com/wp-content/uploads/Trapdoor-C2-Domains.csv trapdoor.csv 1048576
    download https://raw.githubusercontent.com/infobloxopen/threat-intelligence/9cd319c36e4caacf5b8c3b1fd9276f0e19b2732f/indicators/csv/help_tds_hotejka_20261015_iocs.csv help-tds.csv 1048576
    (
        cd -- "$stage"
        sha256sum --strict --check <<'SUMS'
c3fdfa2c133e57ca97cf0fff835b7f3ed114539ac3801a53c9fde2250233727d  pushpaganda.csv
68c6f50c4b31591b87cebfb58c2a4ad0fa4bf52b7c9e617ec02698b3a457ee34  trapdoor.csv
041c6f3c1698571da9d19d9a955e6b5f063a7878b7cbbb4a1b7e806c856e657a  help-tds.csv
SUMS
    )
fi
cp -- "$here/nytimes.labels.json" "$here/pcgamer.labels.json" "$here/pcgamer.clicks.json" "$stage/"
# The publisher HTML and script were captured before recording the click in a NIC-less VM.
cp -- "$here/fixtures/"{kutlat-click.har,kutlat-click.labels.json,kutlat-click.clicks.json} "$stage/"
(
    cd -- "$stage"
    sha256sum --strict --check <<'SUMS'
5e9092d1544666cf50fb4ba4020f2ac4580afc0990e0be0621ac17e339d8f7d0  kutlat-click.har
SUMS
)
if [[ $with_ranked_scans == true ]]; then
    python3 "$here/ranked-scans.py" "$stage"
fi
mv -T --no-clobber -- "$stage" "$destination"
if [[ -d "$stage" ]]; then
    printf 'Corpus destination already exists. Choose a new directory.\n' >&2
    exit 2
fi
