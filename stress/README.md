# Offline advertising stress testing

The suite passes recorded HTTP requests and responses through the production ad
blocker's request and response hooks. Its main checks cover first-party and
third-party ad requests, unwanted redirects, cosmetic filtering of captured
HTML, and legitimate publisher requests that should pass. The default run treats captures as data
and measures the addon's HTTP decisions. The optional browser run executes
recorded pages in a disconnected VM to measure click-triggered windows and
the effect of the addon's HTTP decisions on them.

## Prepare a disposable Proxmox VE VM

1. Create a fresh Linux VM with Docker Engine 25 or newer, cgroup v2, Bash,
   Python 3.10 or newer, and current security updates. Use 2 vCPUs and 4 GiB
   RAM for the measured workloads below. Budget additional guest RAM for
   larger runs and leave room for Linux and Docker outside the sandbox budget.
   Leave out shared folders, device passthrough, credentials, and production
   proxy configuration.
2. Install current [gVisor](https://gvisor.dev/docs/user_guide/install/) from a
   verified release or its signed package repository. Register the `runsc`
   runtime with Docker as the install guide describes. Prepare the trusted image
   and corpus during setup on an isolated network or import them using a
   read-only virtual disk.
3. Disconnect the VM's virtual NIC in Proxmox before replay. Run the commands
   from the VM console. Export the plain JSON summary and destroy the disposable
   VM or revert it to its clean snapshot.

Keep browser replay in the disconnected VM and run Docker with
`--bridge=none` so the guest has only loopback. gVisor and the disconnected VM
provide isolation for browser replay. Playwright defaults to running Chromium
with its internal sandbox disabled.
[Playwright Chromium sandbox option](https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch-option-chromium-sandbox)

The launcher requires `runsc`, disables container networking, and verifies that the process
runs as UID 10001 with at most a loopback interface before opening its input.
It drops all capabilities, prevents privilege escalation, uses a read-only
root filesystem and a fresh read-only copy of the selected corpus files. It
publishes no ports, mounts no host sockets, disables container swap, and caps
the report at 128 KiB.

## Prepare and run

Run these from the repo root while trusted setup access is available.

```sh
docker build -t mitm-adblock:stress .
./stress/stage-public.sh --with-ranked-scans ./stress-corpus
```

The staging script downloads EasyList, EasyPrivacy,
[Fanboy’s Annoyance List](https://easylist.to/#fanboys-annoyance-list),
[HaGeZi Threat Intelligence Feeds Full](https://github.com/hagezi/dns-blocklists#tif),
[HaGeZi Pop-Up Ads](https://github.com/hagezi/dns-blocklists#popupads),
[OISD Big](https://oisd.nl/setup/adblockplus),
[Peter Lowe’s Ad and Tracking Server List](https://pgl.yoyo.org/adservers/),
[uBlock Origin Badware Risks](https://github.com/uBlockOrigin/uAssets/blob/master/filters/badware.txt), and
[URLhaus Online](https://github.com/curbengh/urlhaus-filter)
from their publishers. The starter corpus uses three checksum-pinned publisher
captures. Keep the resulting directory to rerun with the same filter and
capture snapshots. Omit `--with-ranked-scans` for the pinned publisher tests
alone. Replay performs no downloads.

The [WebSci ad-blocking study download](https://gvrkiran.github.io/adblock/)
supplies a real advertising-heavy HAR with hundreds of requests, trackers,
ad auctions, and redirects. The starter expectations check its publisher
document, ad viewability beacon, ad auction request, ad redirects, and
first-party ad and tracking endpoints. A recorded first-party account data
request is an allow control. Three historical first-party ad requests remain
coverage probes after the removal of the bundled site rules. The capture omits HTTP headers and response
bodies. Its recorded MIME type identifies HTML responses and its HAR
`redirectURL` supplies the target of a redirect when the recorded Location
header is unavailable.

The [October 2026 Common Crawl archive](https://www.commoncrawl.org/blog/october-2026-crawl-archive-now-available)
adds the original PC Gamer home page HTML and its HTTP CSP. The staging script
imports just the selected response record. It supplies the document's HTML
Accept type because the record contains the response only. The expectation
checks for the stylesheet rule that hides its exit-intent newsletter overlay.

Once the guest NIC is disconnected, run:

```sh
python3 stress/run.py --check
python3 stress/run.py ./stress-corpus --repeat 20 > stress-report.json
```

### Automatically selected public captures

`--with-ranked-scans` intersects the current [Tranco ranking](https://tranco-list.eu/)
with HaGeZi's maintained [NSFW and Anti-Piracy lists](https://github.com/hagezi/dns-blocklists).
It looks for recent [public urlscan reports](https://urlscan.io/docs/search/)
for the highest-ranked publishers in each group (adult listed, piracy listed,
and listed in both). It selects up to eight reports per group drawn from the
first 16 eligible domains within the top 150,000. The staged TIF Full snapshot
screens out listed apex domains from the selection pool. Eligibility requires
a successful final page on the same publisher and enough recorded traffic to
exercise the blocker. The downloader contacts the list publishers and public
archive, and the guest replays their transaction data offline.

Each imported HAR omits response bodies, cookies, and POST data. Its replay
report records the public scan ID, rank, group, and SHA-256 hashes of the
source report and the ranking and category snapshots. A publisher document
allow probe helps spot breakage. Cohort sizes vary with archive availability.
Visible redirect chains are preserved as metadata. Their hop counts record
what the public reports show without inferring intermediate HTTP statuses
or addon decisions for those hops. Ad recall requires verified labels on the
individual requests. Run again with
`--infer-resource-types` to compare results using the captured browser resource
type for requests that lack `Sec-Fetch-Dest`.

### Replay captured clicks

Build the browser image before transferring it into the guest. Use the same
`mitm-adblock:stress` build as the HTTP suite.

```sh
docker build -f stress/Dockerfile.browser -t mitm-adblock:stress-browser .
# In the NIC-less VM, with both images already staged
python3 stress/run.py --clicks --check
python3 stress/run.py --clicks ./stress-corpus > click-report.json
```

The pinned PC Gamer capture supplies an allow control. Its actual About Us
link opens a new window and the article list remains visible on the opener.

The pinned KutLat capture supplies an unwanted-window case. It includes the
publisher HTML, its original first-party click handler, and the initial
affiliate navigation recorded after a real Chromium click on “Click to
continue.” The VM intercepted the request locally. The HAR omits the affiliate
response, cookies and POST data, and the publisher HTML has its anonymous form
token stripped. The HTTP replay checks that the page and its script load and
the affiliate navigation is blocked. The browser replay also checks that the
publisher stays visible and records whether the browser still opens a tab.
[Original AdGuard report](https://github.com/AdguardTeam/AdguardFilters/issues/243111)

To add another ad case, collect or import a sanitized, full HAR from an
isolated browser session that recorded a normal click and the extra window
it triggered. Keep any live recording in a separate disposable guest on an
isolated network and use a fresh browser profile. Use a context-wide HAR
with full mode and embedded content so it includes the original publisher
document, the scripts and resources that run the click, any intervening
redirects, and the first unwanted landing request. Save the clicked element's
selector and the intended content or navigation on the opener. Screen
recordings and request tables can help identify the click but they lack the
page and handler bodies needed for replay. The automatically selected report
HARs are request-only. [Playwright HAR recording options](https://playwright.dev/python/docs/api/class-browser#browser-new-context-option-record-har-path)

Save the assertions in a `<capture>.clicks.json` array beside the HAR. Each
case uses these fields.

| Field | Value |
|---|---|
| `expect` | `block` for an unsolicited ad window or `allow` for an intentional new window |
| `start_url` | Exact HTTP(S) publisher document URL in the HAR |
| `click` | CSS selector for the single visible element the user clicked |
| `opener_url` | Exact expected URL of the original page after the click |
| `opener_selector` | CSS selector for intended publisher content that must stay visible |
| `popup_url` | Exact terminal navigation URL to score |

Use the recorded GET/HEAD resources and response bodies. The opener and ad
handler are replayed with their captured content. The runner answers the
designated terminal navigation with an empty local response when allowed.
It denies unrecorded requests and disables service workers, WebSockets, and
downloads. Keep an expected ad's request record in the HAR and omit its
landing-page body. If a URL was recorded with different responses, keep the
exchange used for that click. Keep the capture and its provenance together.

A fresh unfiltered Chromium context must reproduce the new window and the
designated request with a real browser click before the same capture is scored
with the addon. The JSON reports whether the opener remained usable, the
number of new windows, and whether delivery was blocked. A 403 on the popup
can stop the advertiser while leaving the extra window open. Headless replay
does not measure window stacking. A failed baseline is an incomplete test.
For ad cases, a missing navigation or script during the click also makes the
test incomplete. The runner exits 2 for an
incomplete test and 1 for a filtering or opener regression.

Browser replay defaults to three runs per case, 2,048 MiB RAM, two CPUs, 128
tasks, and 240 seconds. Use at most eight click cases and 24 total baseline and
filtered pairs per run. Each interaction observes the two seconds after the
click. Divide a larger batch and size the resource limits for the resulting
workload.

### Optional historical campaign probes

To stage the publisher capture with three additional checksum-pinned campaign
samples, run during guest setup:

```sh
./stress/stage-public.sh --with-campaigns ./stress-corpus-with-campaigns
```

Campaign scores describe direct document requests to published historical
hostnames. Use them as supplemental list diagnostics. Use the publisher
expectations and allow controls to judge changes to ad and annoyance filtering.

- [HUMAN Satori's Pushpaganda investigation](https://www.humansecurity.com/learn/resources/satori-threat-intelligence-alert-pushpaganda-manipulates-google-discovery-feeds-with-ai-generated-content-to-spread-malicious-notifications/)
  supplies campaign domains involved in malicious push advertising. The
  runner checks each domain as an offline document request.
- [HUMAN Satori's Trapdoor investigation](https://www.humansecurity.com/learn/resources/satori-threat-intelligence-alert-trapdoor-funnels-malvertising-into-ad-fraud/)
  supplies command-and-control hostnames. The report shows how many of these
  hostnames the engine blocks on direct document requests.
- [Infoblox's Help TDS investigation](https://www.infoblox.com/blog/threat-intelligence/2026/10/inside-help-tds-hotejka-cloudflare-pages-and-predictive-detection)
  supplies tech-support scam infrastructure. The probe uses only indicators
  classified as malicious domains and checks the specific published hostnames,
  including individual tenants on shared hosting.

When the Badware Risks snapshot is present, the runner also probes its
hostname-only `$all` rules and reports them as `badware_all_rules`. This
checks how the engine applies the configured feed to navigations.

### Size the sandbox for the workload

The default HTTP replay budgets are 1,536 MiB RAM, one CPU, 64 tasks, and 120 seconds.
The runner accepts `--memory-mib`, `--cpus`, `--pids-limit`, and
`--timeout-seconds` overrides. For larger filter snapshots, more HTML bodies,
or slower guests, size these budgets for the full run and keep the same
corpus and expectations. An OOM kill or a timeout fails the run as a
capacity error and names the configured budget.

Measured under gVisor in disconnected Proxmox guests with 2 vCPUs and 4 GiB
RAM. The proxy startup runs loaded the cached default lists and served local
HTTP probes. The rebuild measured compilation with the previous engine still
resident.

| List profile and workload | Peak cgroup RAM |
|---|---:|
| Previous defaults with TIF Medium, proxy startup | 251 MiB |
| TIF Full and Pop-Up Ads defaults, proxy startup | 647 MiB |
| TIF Full and Pop-Up Ads defaults, offline engine rebuild | 771 MiB |
| Maintained defaults with Fanboy’s Annoyance List, publisher replay | 682 MiB |
| Maintained defaults, publisher and 22 ranked reports, HTTP replay | 679 MiB |
| Maintained defaults, Chromium and three captured publisher click pairs | 1,036 MiB |

The 1,536 MiB default provides headroom above the measured rebuild for list
growth and concurrent work. Account for the rebuild and normal traffic when
sizing a persistent proxy. Measure captures with large response bodies
separately. The starter corpus includes two captured HTML documents and the
KutLat click handler.

To size a new workload, use a disconnected guest with enough memory to
complete the run. Measure `memory.peak`, `pids.peak` where available, and
`cpu.stat` from the container's cgroup or a dedicated parent cgroup. Use the
run's elapsed time and leave headroom for input variation and runtime
overhead. [Linux cgroup v2 counters](https://docs.kernel.org/admin-guide/cgroup-v2.html)

`--check` starts the hardened container without a corpus. An unavailable
runtime or invalid input fails the command. Replay exits 1 on a label mismatch
or a failed HTTP replay, and 2 on setup, validation, or capacity failure.
Campaign misses are coverage data. The JSON includes the configured resource
limits, image ID, filter and capture hashes, counts for blocks, redirects,
available HTML bodies and cosmetic injections, addon-hook p95, and up to 50
failing capture entry numbers. It contains no URLs, filter text, headers, or
response bodies. Counts include all repetitions unless the field is `entries`
or `document_probes`. The published redirect chain and hop counts also refer
to one pass through the archived metadata.

## Add intrusive advertising captures

Use genuine archived, sanitized HARs with bodies for meaningful cosmetic
coverage. Collect ordinary page visits and relevant clicks that show
publisher-hosted ads, pop-unders, fake play buttons, notification bait, or
ad overlays. Record the requests and redirects associated with each
annoyance and label the legitimate publisher content or interaction that
should still work. For cosmetic filtering, label a captured HTML document
with a known hide rule as `inject`. Keep the original HTTP context,
including Referer, Sec-Fetch-Dest, response Content-Type, and CSP when available.
Remove authentication material and personal data before staging. For more
real ad traffic and first-party controls, the
[RegTrack research corpus](https://github.com/ubc-spg/RegTrack#data-availability)
offers raw desktop and mobile browser HARs. Select individual captures within
the size limits below.

Keep the corpus directory flat. It requires `easylist.txt`, `easyprivacy.txt`,
and supports `tif-full.txt`, `tif-medium.txt`, `popupads.txt`, `annoyances.txt`,
`oisd-big.txt`, `peter-lowe.txt`,
`badware.txt`, and `urlhaus-online.txt` filter snapshots. For an offline ThreatFox comparison, add
a locally prepared `threat-domains.txt` hostname snapshot of up to 8 MiB. Use one HaGeZi tier per profile. It accepts
up to 32 uncompressed `*.har` files, optional `<capture>.labels.json` and
`<capture>.clicks.json` sidecars,
and `pushpaganda.csv`, `trapdoor.csv`, and `help-tds.csv`. Each campaign may
have up to 5,000 CSV rows. The size limits are 32 MiB per HAR, 8 MiB each for
EasyList, EasyPrivacy, and Fanboy’s Annoyance List, 64 MiB for TIF Full, and 16 MiB each for TIF Medium
and OISD, 4 MiB for Pop-Up Ads, and 32 MiB for URLhaus Online. The Badware Risks and Peter Lowe lists, each sidecar, and each
campaign CSV can be up to 1 MiB. The total corpus can be up to 128 MiB and
expectations can use up to 64 distinct families. Split larger corpora into batches. The entry count times
the repeat count is limited to 100,000 per run.

For a capture named `popunder.har`, `popunder.labels.json` uses zero-based
indices into its `log.entries` array. For example, if entry 7 is the confirmed
ad delivery request and entry 12 is a publisher document:

```json
{
  "7": {"expect": "block", "family": "popunder"},
  "12": {"expect": "allow", "family": "publisher_document"}
}
```

An `inject` label can include a `css_contains` string of up to 1,024
characters to require a specific fragment in the injected stylesheet. This
checks emitted styling. Browser tests check whether it actually hides the
captured elements and preserves the controls.

A label with `"probe": true` records a coverage finding in `probe_misses`
without failing replay. Use probes for historical targets whose support
depends on what current maintained lists still cover.

The report locates mismatches by capture name and entry index. A reported
redirect is a recorded HTTP 3xx response other than 304. Use `stop_redirect`
when the original request or the outgoing redirect should be blocked. Use
`block_redirect` to require an outgoing redirect block at the response hook.
The `blocked` and `allowed` counters show request-hook outcomes.
`blocked_redirects` counts both request and response blocks on recorded
redirect hops, with `blocked_redirect_destinations` counting the response
blocks. Each hop is evaluated independently.
