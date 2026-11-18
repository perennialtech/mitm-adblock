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
[HaGeZi Threat Intelligence Feeds Medium](https://github.com/hagezi/dns-blocklists#tifmedium),
[OISD Big](https://oisd.nl/setup/adblockplus), and
[uBlock Origin Badware Risks](https://github.com/uBlockOrigin/uAssets/blob/master/filters/badware.txt)
from their publishers, copies the bundled first-party rules, and fetches two
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
  runner checks each domain as an offline document request and reports those
  results independently. These indicators provide domain-level coverage.
- The Badware Risks check probes bare document URLs for hostname-only `$all`
  rules from the downloaded feed and reports results as `badware_all_rules`.
  This measures how the configured engine applies the feed to navigations.
  The separately sourced Pushpaganda indicators measure campaign coverage.

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

These workloads were measured under gVisor in a disconnected Proxmox guest
with 2 vCPUs and 4 GiB RAM. Both builds used the same six list snapshots,
including Badware Risks, and replayed the 316-entry publisher HAR 100 times
under a one-core quota.

| Build | Peak cgroup RAM | Peak cgroup tasks | Replay elapsed |
|---|---:|---:|---:|
| Previous Python binding | 883 MiB | 30 | 15.1 s |
| adblock-rust 0.13.6 | 221 MiB | 29 | 12.4 s |

The 1,536 MiB default provides headroom for larger list snapshots and captures.
The starter HAR omits response bodies. Measure workloads with large response
bodies separately.

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
and supports optional `tif-medium.txt`, `first-party.txt`, `oisd-big.txt`, and `badware.txt`
filter snapshots. It accepts
up to 32 uncompressed `*.har` files, optional `<capture>.labels.json` sidecars,
and the optional `pushpaganda.csv`. Each HAR can be up to 32 MiB, each EasyList
or EasyPrivacy snapshot up to 8 MiB, and each HaGeZi or OISD snapshot up to
16 MiB. The first-party and Badware Risks lists, each sidecar, and the CSV can be up to 1 MiB
each. The total corpus can be up to 128 MiB and expectations can use up to 64
distinct families. Split larger corpora into batches. The entry count times
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
