# Offline malvertising stress testing

The suite passes recorded HTTP requests and responses through the production ad
blocker's request and response hooks. It checks request blocking, recorded
redirect responses, and cosmetic rewrites of captured HTML. Capture contents
stay as data inside an offline sandbox. The suite measures the addon at the
HTTP flow level. Browser rendering, JavaScript, push permission prompts, and
TLS, TCP, and QUIC interception are outside its coverage.

## Prepare a disposable Proxmox VE VM

1. Create a fresh Linux VM with Docker Engine 25 or newer, cgroup v2, Bash,
   Python 3.10 or newer, and current security updates. A guest with 2 vCPUs and
   2 GiB RAM is sufficient for the default limits. Leave out shared folders,
   device passthrough, credentials, and production proxy configuration.
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
root filesystem and a fresh read-only copy of the selected corpus files, and
limits the replay to one CPU, 768 MiB RAM, 64 processes, 120 seconds, and a
128 KiB report. It publishes no ports and mounts no host sockets.

## Prepare and run

Run these from the repo root while trusted setup access is available.

```sh
docker build -t mitm-adblock:stress .
./stress/stage-public.sh ./stress-corpus
```

The staging script downloads EasyList and EasyPrivacy from their publisher and
fetches two checksum-pinned public data sources. Keep the resulting directory
to rerun with the same filter snapshots. The workload performs no downloads.

- The [WebSci ad-blocking study download](https://gvrkiran.github.io/adblock/)
  supplies a real advertising-heavy HAR with hundreds of requests, trackers,
  ad auctions, and redirects. The starter expectations check its publisher
  document, ad viewability beacon, ad auction request, and ad redirect. The
  capture omits HTTP headers and response bodies. Its recorded MIME type
  still identifies HTML responses for the coverage report.
- [HUMAN Satori's Pushpaganda investigation](https://www.humansecurity.com/learn/resources/satori-threat-intelligence-alert-pushpaganda-manipulates-google-discovery-feeds-with-ai-generated-content-to-spread-malicious-notifications/)
  supplies campaign domains involved in malicious push advertising. The
  runner checks each domain as an offline document request and reports those
  results independently. These indicators provide domain-level coverage.

Once the guest NIC is disconnected, run:

```sh
python3 stress/run.py --check
python3 stress/run.py ./stress-corpus --repeat 20 > stress-report.json
```

`--check` starts the hardened container without a corpus. An unavailable
runtime or invalid input fails the command. Replay exits 1 on a label mismatch
or a failed HTTP replay, and 2 on setup or validation failure. Campaign misses
are coverage data. The JSON includes the image ID, filter and capture hashes, counts for
blocks, redirects, available HTML bodies and cosmetic injections, addon-hook
p95, and up to 50 failing capture entry numbers. It contains no URLs, filter
text, headers, or response bodies. Counts include all repetitions unless the
field is `entries` or `document_probes`.

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

Keep the corpus directory flat. It accepts `easylist.txt`, `easyprivacy.txt`,
up to 32 uncompressed `*.har` files, optional `<capture>.labels.json` sidecars,
and the optional `pushpaganda.csv`. Each HAR can be up to 32 MiB, each filter
list up to 8 MiB, and each sidecar or CSV up to 1 MiB. The total corpus can be
up to 128 MiB and expectations can use up to 64 distinct families. Split larger corpora into batches. The entry count times
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
redirect is a recorded HTTP 3xx response other than 304. Each recorded hop is
evaluated independently, so a blocked hop measures the addon's behavior on
that request and later hops still contribute their own observations.
