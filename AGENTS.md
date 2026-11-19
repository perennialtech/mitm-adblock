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

# Stress testing

Spin up a fresh disposable Proxmox VE VM before running the advertising stress
suite. Follow [the stress runbook](stress/README.md). Stage the image, gVisor,
filter lists, and captures, then disconnect the VM's virtual NIC before replay.

Use the offline `runsc` launcher for captured traffic. Keep the guest off the
production LAN during replay and keep host shares, device passthrough, Docker
sockets, browser profiles, production CA keys, and credentials out of the guest
and sandbox. Treat the captures as untrusted data. Retain the JSON summary and
discard or revert the guest after the run.
