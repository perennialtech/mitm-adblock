# Stress testing

Spin up a fresh disposable Proxmox VE VM before running the malvertising stress
suite. Follow [the stress runbook](stress/README.md). Stage the image, gVisor,
filter lists, and captures, then disconnect the VM's virtual NIC before replay.

Use the offline `runsc` launcher for captured traffic. Keep the guest off the
production LAN during replay and keep host shares, device passthrough, Docker
sockets, browser profiles, production CA keys, and credentials out of the guest
and sandbox. Treat the captures as untrusted data. Retain the JSON summary and
discard or revert the guest after the run.
