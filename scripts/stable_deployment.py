"""Seal, activate, and launch a reviewed local Fedora release."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from tempfile import TemporaryDirectory, mkdtemp


def checked(path, kind, *, private=False):
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or mode & 0o7022:
        raise ValueError(f"Unsafe deployment entry: {path.name}")
    if private and mode != 0o700:
        raise ValueError(f"Expected a private directory: {path.name}")


def digest(path):
    checked(path, stat.S_ISREG)
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def inventory(path, *, venv=False):
    checked(path, stat.S_ISDIR)
    entries = {}

    def visit(directory):
        for item in sorted(directory.iterdir()):
            relative = item.relative_to(path).as_posix()
            mode = item.lstat().st_mode
            if venv and relative == "lib64" and stat.S_ISLNK(mode):
                if os.readlink(item) != "lib":
                    raise ValueError("Unexpected virtual environment library link.")
                entries[relative] = ["link", "lib"]
            elif stat.S_ISDIR(mode):
                checked(item, stat.S_ISDIR)
                entries[relative] = ["directory", stat.S_IMODE(mode)]
                visit(item)
            else:
                entries[relative] = ["file", stat.S_IMODE(mode), digest(item)]

    visit(path)
    return entries


def release_inventory(release):
    source = release / "source"
    venv = release / ".venv"
    for directory in (release, source, source / "recon", venv, venv / "bin"):
        checked(directory, stat.S_ISDIR)
    if {entry.name for entry in source.iterdir()} != {"server.py", "recon"}:
        raise ValueError("Release source must contain only server.py and recon/.")
    checked(source / "server.py", stat.S_ISREG)
    checked(venv / "bin/python", stat.S_ISREG)
    return {"version": release.name, "source": inventory(source), "venv": inventory(venv, venv=True)}


def atomic_json(path, data):
    with TemporaryDirectory(prefix=".metadata-", dir=path.parent) as scratch:
        temp = Path(scratch) / "data"
        temp.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
        temp.replace(path)


def check_runtime(root, manifest):
    runtime = root / "runtime"
    checked(runtime, stat.S_ISDIR, private=True)
    for name in ("config", "output"):
        checked(runtime / name, stat.S_ISDIR, private=True)
    code = {p.name for p in runtime.iterdir()} - {"config", "output"}
    if code - {"server.py", "recon"}:
        raise ValueError("Unexpected entries in the runtime directory.")
    if manifest is not None:
        observed = {}
        checked(runtime / "recon", stat.S_ISDIR)
        observed["recon"] = ["directory", stat.S_IMODE((runtime / "recon").stat().st_mode)]
        observed.update({"recon/" + name: value for name, value in inventory(runtime / "recon").items()})
        server = runtime / "server.py"
        observed["server.py"] = ["file", stat.S_IMODE(server.lstat().st_mode), digest(server)]
        if observed != manifest["source"]:
            raise ValueError("Active source does not match the sealed release.")
    return runtime


def operate(args, root, lock):
    selector = root / "deployment-metadata.json"
    version, checksum = args.version, args.manifest_sha256
    if args.action in {"verify", "serve"}:
        if version is not None:
            raise ValueError("The active version comes from deployment-metadata.json.")
        checked(selector, stat.S_ISREG)
        active = json.loads(selector.read_text(encoding="utf-8"))
        version, checksum = active["version"], active["manifest_sha256"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a release version in X.Y.Z format.")
    releases = root / "releases"
    checked(releases, stat.S_ISDIR)
    release = releases / version
    checked(release, stat.S_ISDIR)
    manifest_path = release / "manifest.json"
    if args.action == "seal":
        if checksum is not None or os.path.lexists(manifest_path):
            raise ValueError("Sealing requires a new release without a manifest.")
        atomic_json(manifest_path, release_inventory(release))
        print(digest(manifest_path))
        return
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Expected the recorded SHA-256 of the release manifest.")
    if digest(manifest_path) != checksum:
        raise ValueError("Release manifest checksum mismatch.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest != release_inventory(release):
        raise ValueError("Release files do not match the sealed inventory.")
    if args.action == "activate":
        runtime = check_runtime(root, None)
        if os.path.lexists(selector):
            checked(selector, stat.S_ISREG)
        elif {path.name for path in runtime.iterdir()} != {"config", "output"}:
            raise ValueError("First activation requires an empty runtime code area.")
        previous_code = []
        for name, kind in (("recon", stat.S_ISDIR), ("server.py", stat.S_ISREG)):
            if os.path.lexists(runtime / name):
                checked(runtime / name, kind)
                previous_code.append(runtime / name)
        with TemporaryDirectory(prefix=".activation-", dir=root) as scratch:
            staged = Path(scratch)
            shutil.copytree(release / "source/recon", staged / "recon")
            shutil.copy2(release / "source/server.py", staged / "server.py")
            # The launch lock stays exclusive until the copied source matches this selector.
            atomic_json(selector, {"version": version, "manifest_sha256": checksum})
            if previous_code:
                retired = Path(mkdtemp(prefix=".retired-code-", dir=root))
                for path in previous_code:
                    path.replace(retired / path.name)
                print(f"Previous runtime code kept in {retired.name}.", file=sys.stderr)
            (staged / "recon").replace(runtime / "recon")
            (staged / "server.py").replace(runtime / "server.py")
    runtime = check_runtime(root, manifest)
    if args.action == "serve":
        os.chdir(runtime)
        os.set_inheritable(lock, True)
        python = release / ".venv/bin/python"
        os.execv(python, [str(python), "-E", "-s", "-B", str(runtime / "server.py")])
    print(f"Verified recon-mcp {version} ({checksum})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seal", "activate", "verify", "serve"))
    parser.add_argument("root", type=Path)
    parser.add_argument("version", nargs="?")
    parser.add_argument("manifest_sha256", nargs="?")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("The deployment root must be a physical absolute path.")
    checked(root, stat.S_ISDIR, private=True)
    lock_flags = os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDWR
    lock = os.open(root / ".deployment.lock", lock_flags, 0o600)
    try:
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("Unsafe deployment lock.")
        exclusive = args.action in {"seal", "activate"}
        fcntl.flock(lock, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        operate(args, root, lock)
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        sys.exit(f"Stable deployment refused: {exc}")
