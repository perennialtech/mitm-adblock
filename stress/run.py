#!/usr/bin/env python3
"""Launch a bounded offline replay using the local Docker daemon's runsc runtime."""

import argparse
from contextlib import contextmanager
import json
import os
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

MIB = 1024 * 1024
RULES = {"easylist.txt", "easyprivacy.txt"}
OPTIONAL_RULES = {
    "adguard-base.txt": 8 * MIB,
    "tif-medium.txt": 16 * MIB,
    "tif-full.txt": 64 * MIB,
    "popupads.txt": 4 * MIB,
    "annoyances.txt": 8 * MIB,
    "oisd-big.txt": 16 * MIB,
    "peter-lowe.txt": MIB,
    "badware.txt": MIB,
    "threat-domains.txt": 8 * MIB,
    "urlhaus-online.txt": 32 * MIB,
}
CAMPAIGNS = {"pushpaganda.csv", "trapdoor.csv", "help-tds.csv"}
CAPTURE_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,90}\.har")
MAX_CAPTURES = 32
MAX_REPORT = 128 * 1024
IMAGE = "mitm-adblock:stress"
BROWSER_IMAGE = "mitm-adblock:stress-browser"


def docker(*args):
    result = subprocess.run(
        ["docker", *args], check=True, stdout=subprocess.PIPE, timeout=15, text=True
    )
    return result.stdout.strip()


def preflight(image_name=IMAGE):
    context = docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
    if any(not url.startswith("unix:///") for url in (context, os.environ.get("DOCKER_HOST") or context)):
        raise ValueError("Select a local Docker context backed by a Unix socket.")
    cgroup, memory, swap, cpu, pids, runtime = docker(
        "info", "--format",
        '{{.CgroupVersion}} {{.MemoryLimit}} {{.SwapLimit}} {{.CPUCfsQuota}} {{.PidsLimit}} '
        '{{json (index .Runtimes "runsc")}}',
    ).split(maxsplit=5)
    if cgroup != "2" or {memory, swap, cpu, pids} != {"true"}:
        raise ValueError("Docker must enforce CPU, memory, swap and process limits using cgroup v2.")
    settings = json.loads(runtime) or {}
    if Path(settings.get("path", "")).name != "runsc":
        raise ValueError("Docker's runsc runtime is required. See stress/README.md.")
    image = json.loads(docker("image", "inspect", "--format", "{{json .}}", image_name))
    if image["Config"].get("Volumes"):
        raise ValueError("The replay image must have no declared volumes.")
    return image["Id"]


@contextmanager
def directory_fd(source):
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def copy_corpus(source, destination):
    # Open relative to one directory descriptor. Never traverse user-supplied
    # symlinks or give the container the original directory as a mount.
    total = 0
    with directory_fd(source) as directory:
        names = set()
        with os.scandir(directory) as members:
            for member in members:
                names.add(member.name)
                if len(names) > 3 * MAX_CAPTURES + len(RULES) + len(OPTIONAL_RULES) + len(CAMPAIGNS):
                    raise ValueError("The corpus contains too many files.")
        captures = {name for name in names if CAPTURE_NAME.fullmatch(name)}
        labels = {name.removesuffix(".har") + ".labels.json" for name in captures}
        clicks = {name.removesuffix(".har") + ".clicks.json" for name in captures}
        allowed = RULES | OPTIONAL_RULES.keys() | CAMPAIGNS | captures | labels | clicks
        if not RULES <= names or not 1 <= len(captures) <= MAX_CAPTURES or names - allowed:
            raise ValueError("Corpus needs both base lists and 1–32 HARs. Extra files must be supported lists, CSVs or paired sidecars.")
        limits = dict.fromkeys(captures, 32 * MIB)
        limits.update(dict.fromkeys(RULES, 8 * MIB))
        limits.update(OPTIONAL_RULES)
        for name in sorted(names):
            limit = limits.get(name, MIB)
            with os.fdopen(
                os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory), "rb"
            ) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
                    raise ValueError("Corpus members must be nonempty regular files within the documented size limits.")
                data = stream.read(min(limit, 128 * MIB - total) + 1)
                total += len(data)
                if len(data) != info.st_size or total > 128 * MIB:
                    raise ValueError("The corpus exceeded 128 MiB or changed while being copied.")
                target = destination / name
                target.write_bytes(data)
                target.chmod(0o444)


def read_report(name, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    report = bytearray()
    with subprocess.Popen(
        ["docker", "start", "--attach", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as process, selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while (remaining := deadline - time.monotonic()) > 0:
                if not selector.select(min(remaining, 60)):
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    try:
                        exit_code = process.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        break
                    return report, exit_code
                report.extend(chunk)
                if len(report) > MAX_REPORT:
                    raise ValueError("Replay exceeded the report size limit.")
            raise ValueError(
                f"Replay exceeded its {timeout_seconds}s wall-clock budget. "
                "Set --timeout-seconds for the intended workload."
            )
        finally:
            if process.poll() is None:
                process.kill()


def run(image, staged, args):
    name = f"mitm-adblock-stress-{uuid.uuid4().hex}"
    memory = f"{args.memory_mib}m"
    browser_options = (
        "--ipc=private", "--shm-size=192m", "--env=HOME=/tmp",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,mode=1777,size=256m",
    ) if args.clicks else ("--ipc=none",)
    script = "replay-clicks.py" if args.clicks else "replay.py"
    try:
        docker(
            "create", "--name", name, "--pull=never", "--runtime=runsc", "--network=none",
            "--user=10001:10001", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", *browser_options, "--cgroupns=private",
            f"--pids-limit={args.pids_limit}", f"--cpus={args.cpus}",
            f"--memory={memory}", f"--memory-swap={memory}",
            "--ulimit=core=0:0", "--ulimit=nofile=256:256", "--no-healthcheck",
            "--log-driver=none",
            "--mount", f"type=bind,src={staged},dst=/replay,readonly,bind-recursive=disabled",
            "--entrypoint=python", image, "-I", "-B", f"/replay/{script}",
            str(args.repeat), str(args.timeout_seconds),
            *(["--check"] if args.check else []),
            *(["--infer-resource-types"] if args.infer_resource_types else []),
        )
        payload, status = read_report(name, args.timeout_seconds)
        if status and docker("inspect", "--format", "{{.State.OOMKilled}}", name) == "true":
            raise ValueError(
                f"Replay exceeded its {args.memory_mib} MiB memory budget. "
                "Set --memory-mib from a measurement of the intended workload."
            )
        try:
            report = json.loads(payload)
        except (ValueError, RecursionError):
            raise ValueError(f"Replay produced no valid JSON report (container exit {status}).") from None
        if not isinstance(report, dict):
            raise ValueError("Replay produced a report with an invalid structure.")
        report["image_id"] = image
        report["resource_limits"] = {
            "memory_mib": args.memory_mib,
            "cpus": args.cpus,
            "pids": args.pids_limit,
            "timeout_seconds": args.timeout_seconds,
        }
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return status
    finally:
        # An attached client timing out or being interrupted does not stop its container.
        try:
            docker("rm", "--force", name)
        except (OSError, subprocess.SubprocessError):
            print(f"Could not confirm removal of {name}.", file=sys.stderr)


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def positive_int(value):
    number = int(value)
    if not 0 < number <= 2**31 - 1:
        raise argparse.ArgumentTypeError("expected a positive 32-bit integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, nargs="?")
    parser.add_argument("--repeat", type=int, choices=range(1, 101), metavar="1..100",
                        help="Repetitions per case (HTTP: 20, browser: 3).")
    parser.add_argument("--memory-mib", type=positive_int,
                        help="Container RAM in MiB, with swap disabled (HTTP: 1536, browser: 2048).")
    parser.add_argument("--cpus", type=positive_int,
                        help="Container CPU quota in cores (HTTP: 1, browser: 2).")
    parser.add_argument("--pids-limit", type=positive_int,
                        help="Container task limit (HTTP: 64, browser: 128).")
    parser.add_argument("--timeout-seconds", type=positive_int,
                        help="Replay wall-clock budget (HTTP: 120s, browser: 240s).")
    parser.add_argument("--infer-resource-types", action="store_true",
                        help="Use captured browser types when Sec-Fetch-Dest is missing.")
    parser.add_argument("--clicks", action="store_true",
                        help="Replay archived browser clicks inside a disconnected guest.")
    parser.add_argument("--check", action="store_true", help="Start the sandbox without any corpus.")
    args = parser.parse_args()
    if (args.corpus is None) == (not args.check):
        parser.error("supply either a corpus directory or --check")
    if args.clicks and args.infer_resource_types:
        parser.error("browser replay already gets resource types from Chromium")
    args.repeat = args.repeat or (3 if args.clicks else 20)
    args.memory_mib = args.memory_mib or (2048 if args.clicks else 1536)
    args.cpus = args.cpus or (2 if args.clicks else 1)
    args.pids_limit = args.pids_limit or (128 if args.clicks else 64)
    args.timeout_seconds = args.timeout_seconds or (240 if args.clicks else 120)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        if args.clicks and {name for _, name in socket.if_nameindex()} - {"lo"}:
            raise ValueError("Browser replay requires a disconnected guest with only loopback interfaces.")
        image = preflight(BROWSER_IMAGE) if args.clicks else preflight()
        with tempfile.TemporaryDirectory(prefix="mitm-stress-", dir="/tmp") as scratch:
            staged = Path(scratch) / "input"
            staged.mkdir(mode=0o755)
            if args.corpus is not None:
                copy_corpus(args.corpus, staged)
            scripts = ("replay.py", "replay-clicks.py") if args.clicks else ("replay.py",)
            for script in scripts:
                code = staged / script
                code.write_bytes(Path(__file__).with_name(script).read_bytes())
                code.chmod(0o444)
            return run(image, staged, args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Stress runner: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
