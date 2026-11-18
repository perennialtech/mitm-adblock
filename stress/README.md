# Offline malvertising stress testing

The suite passes recorded HTTP requests and responses through the production ad
blocker's request and response hooks. It checks request blocking, recorded
redirect responses, and cosmetic rewrites of captured HTML. Capture contents
stay as data inside an offline sandbox. The suite measures the addon at the
HTTP flow level. Browser rendering, JavaScript, push permission prompts, and
TLS, TCP, and QUIC interception are outside its coverage.

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

The same runner can be used for offline replay on a patched Linux workstation
with a trusted local Docker daemon and a working gVisor installation. A VM adds
another boundary when the input includes hostile captures. The launcher
requires `runsc`, disables container networking, and verifies that the process
runs as UID 10001 with at most a loopback interface before opening its input.
It drops all capabilities, prevents privilege escalation, uses a read-only
root filesystem and a fresh read-only copy of the selected corpus files. It
publishes no ports, mounts no host sockets, disables container swap, and caps
the report at 128 KiB.

## Prepare and run

Run these from the repo root while trusted setup access is available.

```sh
docker build -t mitm-adblock:stress .
./stress/stage-public.sh ./stress-corpus
```

The staging script downloads EasyList, EasyPrivacy,
[HaGeZi Threat Intelligence Feeds Full](https://github.com/hagezi/dns-blocklists#tif),
[HaGeZi Pop-Up Ads](https://github.com/hagezi/dns-blocklists#popupads),
[OISD Big](https://oisd.nl/setup/adblockplus), and
[uBlock Origin Badware Risks](https://github.com/uBlockOrigin/uAssets/blob/master/filters/badware.txt)
from their publishers, copies the bundled first-party rules, and fetches four
checksum-pinned public data sources. Keep the resulting directory
to rerun with the same filter snapshots. The workload performs no downloads.

- The [WebSci ad-blocking study download](https://gvrkiran.github.io/adblock/)
  supplies a real advertising-heavy HAR with hundreds of requests, trackers,
  ad auctions, and redirects. The starter expectations check its publisher
  document, ad viewability beacon, ad auction request, ad redirects, and
  first-party ad and tracking endpoints. A recorded first-party account data
  request is an allow control. The capture omits HTTP headers and response
  bodies. Its recorded MIME type
  identifies HTML responses and its HAR `redirectURL` supplies the target of a
  redirect when the recorded Location header is unavailable.
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
- The Badware Risks check probes bare document URLs for hostname-only `$all`
  rules from the downloaded feed and reports results as `badware_all_rules`.
  This measures how the configured engine applies the feed to navigations.
  The three independently published campaign lists measure domain-level
  coverage. Reported indicators are historical observations, and the probes
  represent direct document requests.

Once the guest NIC is disconnected, run:

```sh
python3 stress/run.py --check
python3 stress/run.py ./stress-corpus --repeat 20 > stress-report.json
```

### Size the sandbox for the workload

The default budgets are 1,536 MiB RAM, one CPU, 64 tasks, and 120 seconds.
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

The 1,536 MiB default provides headroom above the measured rebuild for list
growth and concurrent work. Account for the rebuild and normal traffic when
sizing a persistent proxy. Measure captures with large response bodies
separately. The starter HAR omits response bodies.

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
or `document_probes`.

## Add higher-severity captures

Use genuine archived, sanitized HARs with bodies for meaningful cosmetic
coverage. Include intact visits and post-click or redirect captures from
documented abusive campaigns, such as pop-unders, fake play buttons, push
notification bait, scareware redirects, and deceptive download landings. Use
an independent label for the ad delivery request or redirect to block and a
publisher request to allow. For cosmetic filtering, label a captured HTML
document with a known hide rule as `inject`. Keep the original HTTP context,
including Referer, Sec-Fetch-Dest, response Content-Type, and CSP when available.
Remove authentication material and personal data before staging. For more
real ad traffic and first-party controls, the
[RegTrack research corpus](https://github.com/ubc-spg/RegTrack#data-availability)
offers raw desktop and mobile browser HARs. Select individual captures within
the size limits below.

Keep the corpus directory flat. It requires `easylist.txt`, `easyprivacy.txt`,
and supports `tif-full.txt`, `tif-medium.txt`, `popupads.txt`, `first-party.txt`, `oisd-big.txt`,
and `badware.txt` filter snapshots. For an offline ThreatFox comparison, add
a locally prepared `threat-domains.txt` hostname snapshot of up to 8 MiB. Use one HaGeZi tier per profile. It accepts
up to 32 uncompressed `*.har` files, optional `<capture>.labels.json` sidecars,
and `pushpaganda.csv`, `trapdoor.csv`, and `help-tds.csv`. Each campaign may
have up to 5,000 CSV rows. The size limits are 32 MiB per HAR, 8 MiB each for
EasyList and EasyPrivacy, 64 MiB for TIF Full, and 16 MiB each for TIF Medium
and OISD, and 4 MiB for Pop-Up Ads. The first-party and Badware Risks lists, each sidecar, and each
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

The report locates mismatches by capture name and entry index. A reported
redirect is a recorded HTTP 3xx response other than 304. Use `stop_redirect`
when the original request or the outgoing redirect should be blocked. Use
`block_redirect` to require an outgoing redirect block at the response hook.
The `blocked` and `allowed` counters show request-hook outcomes.
`blocked_redirects` counts both request and response blocks on recorded
redirect hops, with `blocked_redirect_destinations` counting the response
blocks. Each hop is evaluated independently.
