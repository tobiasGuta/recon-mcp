"""Fedora directory mode and lock lifecycle regressions."""

import os
import stat
import subprocess
import sys

import pytest

from recon import campaign_lock, campaigns

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux campaign storage"
)


@pytest.mark.parametrize("mask", [0o0000, 0o0002, 0o0022, 0o0077])
def test_campaign_initialization_uses_private_modes(
    campaign_env, monkeypatch, tmp_path, mask
):
    output = tmp_path / "output"
    active = output / "campaigns"
    archive = output / "archived_campaigns"
    monkeypatch.setattr(campaigns, "CAMPAIGNS_DIR", active)
    monkeypatch.setattr(campaigns, "ARCHIVED_CAMPAIGNS_DIR", archive)
    previous = os.umask(mask)
    try:
        created = campaigns.create_campaign("Synthetic", "example.com")
        assert created["ok"], created
        cid = created["campaign_id"]
        assert campaigns.archive_campaign(cid)["ok"]
    finally:
        os.umask(previous)

    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o700 for path in (output, active, archive)
    )
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o700
        for path in archive.rglob("*")
        if path.is_dir()
    )
    assert stat.S_IMODE((output / campaign_lock.LOCK_NAME).stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["parent", "active", "archive"])
def test_unsafe_existing_storage_is_rejected_without_chmod(
    campaign_env, tmp_path, monkeypatch, kind
):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    active = output / "campaigns"
    archive = output / "archived_campaigns"
    monkeypatch.setattr(campaigns, "CAMPAIGNS_DIR", active)
    monkeypatch.setattr(campaigns, "ARCHIVED_CAMPAIGNS_DIR", archive)
    if kind != "parent":
        path = active if kind == "active" else archive
        path.mkdir(mode=0o700)
        mode = 0o755
    else:
        path = output
        mode = 0o775
    path.chmod(mode)
    result = campaigns.create_campaign("Synthetic", "example.com")
    assert result["error_code"] == "campaign_storage_unavailable"
    assert "manually" in result["error"]
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_foreign_owner_is_rejected_before_campaign_access(campaign_env, monkeypatch):
    monkeypatch.setattr(
        campaign_lock.os, "geteuid", lambda: campaign_env.parent.stat().st_uid + 1
    )
    result = campaigns.create_campaign("Synthetic", "example.com")
    assert result["error_code"] == "campaign_storage_unavailable"
    assert "current user" in result["error"]
    assert not campaign_env.exists()


def test_fork_cleanup_closes_child_descriptors_and_preserves_parent_lock(tmp_path):
    # Fork in an isolated, single-threaded interpreter. The child only checks its
    # inherited descriptors and exits without resuming an in-flight operation.
    script = """
import errno, fcntl, os, sys
from pathlib import Path
from recon import campaign_lock, campaigns

root = Path(sys.argv[1])
campaigns.CAMPAIGNS_DIR = root / "active"
campaigns.ARCHIVED_CAMPAIGNS_DIR = root / "archives"
with campaign_lock.campaign_storage_lock():
    fd, = campaign_lock._open_locks
    pid = os.fork()
    if pid == 0:
        try:
            assert not campaign_lock._open_locks
            assert campaign_lock._held.path is None
            try:
                os.fstat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                raise AssertionError("child retained the lock descriptor")
        except BaseException:
            os._exit(1)
        os._exit(0)
    assert os.waitpid(pid, 0)[1] == 0
    competing = os.open(root / campaign_lock.LOCK_NAME, os.O_RDONLY)
    try:
        try:
            fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise AssertionError("child released the parent's lock")
    finally:
        os.close(competing)
assert not campaign_lock._open_locks
with campaign_lock.campaign_storage_lock():
    assert campaign_lock._open_locks
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()


def test_free_threaded_storage_runtime_fails_closed(campaign_env, monkeypatch):
    monkeypatch.setattr(
        campaign_lock.sys, "_is_gil_enabled", lambda: False, raising=False
    )
    result = campaigns.create_campaign("Synthetic", "example.com")
    assert result["error_code"] == "campaign_storage_unavailable"
    assert "GIL-enabled CPython" in result["error"]
    assert not campaign_env.exists()


def test_nested_artifact_directories_use_private_modes(campaign_env):
    from recon.safeio import write_artifact_bytes

    cid = campaigns.create_campaign("Synthetic", "example.com")["campaign_id"]
    directories = campaign_env / cid / "evidence"
    previous = os.umask(0o002)
    try:
        assert write_artifact_bytes(
            cid, "fixture", directories / "one" / "two" / "data.bin", b"data"
        )["sha256"]
    finally:
        os.umask(previous)
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o700
        for path in (directories / "one", directories / "one" / "two")
    )
