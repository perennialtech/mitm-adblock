#!/usr/bin/env python3
"""Launch a bounded offline replay using the local Docker daemon's runsc runtime."""

import argparse
from contextlib import contextmanager
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

MIB = 1024 * 1024
RULES = {"easylist.txt", "easyprivacy.txt"}
INDICATORS = "pushpaganda.csv"
CAPTURE_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,90}\.har")
MAX_REPORT = 128 * 1024
RUN_SECONDS = 120
IMAGE = "mitm-adblock:stress"


def docker(*args):
    result = subprocess.run(
        ["docker", *args], check=True, stdout=subprocess.PIPE, timeout=15, text=True
    )
    return result.stdout.strip()


def preflight():
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
    image = json.loads(docker("image", "inspect", "--format", "{{json .}}", IMAGE))
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
                if len(names) > 67:
                    raise ValueError("The corpus contains too many files.")
        captures = {name for name in names if CAPTURE_NAME.fullmatch(name)}
        labels = {name.removesuffix(".har") + ".labels.json" for name in captures}
        allowed = RULES | {INDICATORS} | captures | labels
        if not RULES <= names or not 1 <= len(captures) <= 32 or names - allowed:
            raise ValueError("Corpus needs both filter lists and 1–32 HARs, with optional paired labels and campaign CSV.")
        for name in sorted(names):
            limit = 32 * MIB if name in captures else 8 * MIB if name in RULES else MIB
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


def read_report(name):
    deadline = time.monotonic() + RUN_SECONDS
    report = bytearray()
    with subprocess.Popen(
        ["docker", "start", "--attach", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as process, selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.select(max(0, deadline - time.monotonic())):
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    exit_code = process.wait(timeout=max(0, deadline - time.monotonic()))
                    return report, exit_code
                report.extend(chunk)
                if len(report) > MAX_REPORT:
                    raise ValueError("Replay exceeded the report size limit.")
                if time.monotonic() >= deadline:
                    break
            raise ValueError("Replay exceeded its wall-clock limit.")
        finally:
            if process.poll() is None:
                process.kill()


def run(image, staged, repeat, check):
    name = f"mitm-adblock-stress-{uuid.uuid4().hex}"
    try:
        docker(
            "create", "--name", name, "--pull=never", "--runtime=runsc", "--network=none",
            "--user=10001:10001", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--ipc=none", "--cgroupns=private",
            "--pids-limit=64", "--cpus=1", "--memory=768m", "--memory-swap=768m",
            "--ulimit=core=0:0", "--ulimit=nofile=256:256", "--no-healthcheck",
            "--log-driver=none",
            "--mount", f"type=bind,src={staged},dst=/replay,readonly,bind-recursive=disabled",
            "--entrypoint=python", image, "-I", "-B", "/replay/replay.py", str(repeat),
            *(["--check"] if check else []),
        )
        payload, status = read_report(name)
        try:
            report = json.loads(payload)
        except (ValueError, RecursionError):
            raise ValueError(f"Replay produced no valid JSON report (container exit {status}).") from None
        if not isinstance(report, dict):
            raise ValueError("Replay produced a report with an invalid structure.")
        report["image_id"] = image
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, nargs="?")
    parser.add_argument("--repeat", type=int, choices=range(1, 101), default=20, metavar="1..100")
    parser.add_argument("--check", action="store_true", help="Start the sandbox without any corpus.")
    args = parser.parse_args()
    if (args.corpus is None) == (not args.check):
        parser.error("supply either a corpus directory or --check")
    signal.signal(signal.SIGTERM, interrupt)
    try:
        image = preflight()
        with tempfile.TemporaryDirectory(prefix="mitm-stress-", dir="/tmp") as scratch:
            staged = Path(scratch) / "input"
            staged.mkdir(mode=0o755)
            if args.corpus is not None:
                copy_corpus(args.corpus, staged)
            code = staged / "replay.py"
            code.write_bytes(Path(__file__).with_name("replay.py").read_bytes())
            code.chmod(0o444)
            return run(image, staged, args.repeat, args.check)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Stress runner: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
