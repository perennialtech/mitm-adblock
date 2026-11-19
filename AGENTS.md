# Project scope

Prioritize intrusive advertising and everyday browsing annoyances. Focus on
first-party ads, pop-ups and pop-unders, ad redirects, overlays, and clutter
left behind by blocked ads. Preserve legitimate page content and interactions.

Favor app connectivity when choosing certificate fallback defaults. Expose
stricter filtering as an operator setting.

Use maintained upstream filter lists for coverage. Keep site-specific rules
out of this repository and measure how upstream subscriptions cover each gap.

Use real publisher captures to verify improvements. Check both the intrusive
behavior and the page functionality that should still work. Treat historical
threat indicator probes as supplemental coverage. Active malware campaign
investigation belongs in dedicated security tooling.

# Verification

Run `./scripts/check-image` from a checkout with Docker Buildx and curl. This
is the gate CI runs before publishing the image.

# Stress testing

Run advertising and browser replays in a fresh disposable Proxmox VE VM.
Stage images, lists and captures on an isolated setup network or import them
on a read-only virtual disk. Keep production credentials, CA keys, personal
browser profiles, host shares and passthrough devices out of the guest.
Keep Docker sockets out of replay containers.

1. Prepare Linux with Docker Engine 25 or later, cgroup v2, Bash, Python 3.10
   or later and Docker’s [gVisor runsc runtime](https://gvisor.dev/docs/user_guide/install/).
   For browser replay, start the guest Docker daemon with `--bridge=none` so
   the guest has only loopback after disconnection.
2. From the repo root in the guest, build `docker build -t mitm-adblock:stress .` and stage
   the corpus with `./stress/stage-public.sh`. For click tests also build
   `docker build -f stress/Dockerfile.browser -t mitm-adblock:stress-browser .`.
   Use `./stress/stage-public.sh --help` for additional capture sets.
3. Disconnect the guest’s virtual NIC in Proxmox. From its console, run
   `python3 stress/run.py --check`, then `python3 stress/run.py stress-corpus`.
   Use `--clicks` on both commands for browser replay. Keep the JSON report
   before destroying or reverting the guest. See `python3 stress/run.py --help`
   for workload limits. When a limit is reached, size it for the same workload
   and rerun with isolation intact.

For a new case, sanitize a real HAR and label both the unwanted behavior and
a legitimate interaction. Capture live clicks with a fresh browser profile
in a separate disposable guest on an isolated network. Retain the page and script bodies needed for a click to
reproduce offline, strip cookies, credentials and personal data, and omit the
unwanted landing page body. Check that an unfiltered replay reproduces the
window before judging the filter. The [fixture directory](stress/fixtures/)
contains a matching HAR, request labels and click assertions.
