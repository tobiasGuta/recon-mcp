"""Exercise deployment operations with private, disposable Linux directories."""

import os
import select
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


GUARD = Path(__file__).resolve().parents[2] / "scripts/stable_deployment.py"


@pytest.fixture
def deployment(tmp_path):
    previous_umask = os.umask(0o077)
    try:
        return create_deployment(tmp_path)
    finally:
        os.umask(previous_umask)


def create_deployment(tmp_path):
    root = tmp_path / "stable"
    root.mkdir(mode=0o700)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    for directory in ("config", "output"):
        (runtime / directory).mkdir(mode=0o700)
    (runtime / "config/scope.json").write_bytes(b"synthetic-policy")
    (runtime / "output/sample-evidence").write_bytes(b"synthetic-evidence")
    for version in ("0.2.0", "0.2.1"):
        release = root / "releases" / version
        (release / "source/recon").mkdir(parents=True)
        (release / "source/recon/__init__.py").write_text(f"VERSION = {version!r}\n")
        (release / "source/server.py").write_text(
            "import sys\nfrom recon import VERSION\n"
            "print(VERSION, flush=True)\nsys.stdin.read()\n"
        )
        (release / ".venv/bin").mkdir(parents=True)
        shutil.copy2(sys._base_executable, release / ".venv/bin/python")
    return root


def command(root, action, *args):
    return [sys.executable, "-I", "-S", "-B", str(GUARD), action, str(root), *args]


def run(root, action, *args, ok=True):
    result = subprocess.run(command(root, action, *args), capture_output=True, text=True, timeout=15)
    assert (result.returncode == 0) == ok, result.stderr
    return result.stdout.strip() if ok else result.stderr


def stage(root, version="0.2.0"):
    checksum = run(root, "seal", version)
    run(root, "activate", version, checksum)
    return checksum


def test_upgrade_and_rollback_preserve_state(deployment):
    checksum = stage(deployment)
    assert run(deployment, "serve") == "0.2.0"
    assert "0.2.0" in run(deployment, "verify")
    stage(deployment, "0.2.1")
    assert run(deployment, "serve") == "0.2.1"
    run(deployment, "activate", "0.2.0", checksum)
    assert run(deployment, "serve") == "0.2.0"
    assert (deployment / "runtime/config/scope.json").read_bytes() == b"synthetic-policy"
    assert (deployment / "runtime/output/sample-evidence").read_bytes() == b"synthetic-evidence"


def test_activation_refuses_running_server(deployment):
    checksum = stage(deployment)
    with subprocess.Popen(command(deployment, "serve"), stdin=subprocess.PIPE, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as server:
        try:
            assert select.select([server.stdout], [], [], 10)[0]
            assert server.stdout.readline() == "0.2.0\n"
            assert "refused" in run(deployment, "activate", "0.2.0", checksum, ok=False)
            assert "0.2.0" in run(deployment, "verify")
        finally:
            server.stdin.close()
            assert server.wait(timeout=10) == 0


@pytest.mark.parametrize("entry", ["runtime/server.py", "releases/0.2.0/.venv/extra"])
def test_modified_or_extra_code_refuses_launch(deployment, entry):
    checksum = stage(deployment)
    unexpected = deployment / entry
    unexpected.touch(mode=0o600)
    unexpected.write_text("print('unexpected execution')\n")
    assert "match" in run(deployment, "serve", ok=False)
    if entry.startswith("runtime/"):
        run(deployment, "activate", "0.2.0", checksum)
        assert run(deployment, "serve") == "0.2.0"
        (retired,) = deployment.glob(".retired-code-*")
        assert (retired / "server.py").read_text() == "print('unexpected execution')\n"


def test_private_directory_symlink_is_rejected(deployment):
    stage(deployment)
    config = deployment / "runtime/config"
    config.rename(deployment / "private")
    config.symlink_to(deployment / "private", target_is_directory=True)
    assert "Unsafe deployment entry" in run(deployment, "serve", ok=False)


def test_activation_does_not_replace_unmanaged_code(deployment):
    existing = deployment / "runtime/server.py"
    existing.write_text("untouched\n")
    checksum = run(deployment, "seal", "0.2.0")
    assert "First activation" in run(deployment, "activate", "0.2.0", checksum, ok=False)
    assert existing.read_text() == "untouched\n"


def test_wrong_manifest_checksum_refuses_activation(deployment):
    run(deployment, "seal", "0.2.0")
    assert "checksum mismatch" in run(deployment, "activate", "0.2.0", "0" * 64, ok=False)
    assert not os.path.lexists(deployment / "deployment-metadata.json")
