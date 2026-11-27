import json
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from recon import campaign_lock, safeio
from recon.audit import write_audit_event
from recon.authorization import get_scope_policy_summary
from recon.campaigns import (
    archive_campaign,
    create_campaign,
    get_archived_campaign,
    get_campaign_paths,
    reauthorize_campaign,
)
from recon.evidence_graph import add_evidence_batch, get_evidence_graph_summary
from recon.integrity import verify_campaign_artifacts
from recon.memory import list_negative_results, record_negative_result

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Campaign transactions require Linux"
)


def setup_campaign():
    created = create_campaign("Synthetic audit", "example.com")
    assert created["ok"], created
    campaign_id = created["campaign_id"]
    return campaign_id, get_campaign_paths(campaign_id)["paths"]


def test_threads_preserve_graph_read_modify_write_and_memory(campaign_env):
    cid, paths = setup_campaign()
    start = threading.Barrier(12)

    def update(index):
        start.wait(timeout=5)
        assert add_evidence_batch(
            cid,
            "thread",
            [{"node_type": "host", "normalized_value": f"{index}.example.test"}],
        )["ok"]
        assert record_negative_result(
            cid, f"{index}.example.test", "review", "synthetic"
        )["ok"]

    with ThreadPoolExecutor(max_workers=12) as workers:
        list(workers.map(update, range(12)))
    assert get_evidence_graph_summary(cid)["node_count"] == 12
    assert list_negative_results(cid)["count"] == 12
    events = [
        json.loads(line) for line in Path(paths["audit_jsonl"]).read_text().splitlines()
    ]
    assert sum(event["tool"] == "add_evidence_batch" for event in events) == 12


PROCESS_SETUP = """
import os, sys
from pathlib import Path
from recon import campaigns
campaigns.CAMPAIGNS_DIR = Path(sys.argv[1])
campaigns.ARCHIVED_CAMPAIGNS_DIR = campaigns.CAMPAIGNS_DIR.with_name("archived_campaigns")
cid = sys.argv[2]
"""


def test_separate_processes_preserve_graph_memory_and_audit(campaign_env):
    cid, paths = setup_campaign()
    script = (
        PROCESS_SETUP
        + """
from recon.evidence_graph import add_evidence_batch
from recon.memory import record_negative_result
for index in range(8):
    name = f"worker-{sys.argv[3]}-{index}.example.test"
    assert add_evidence_batch(cid, "process", [{"node_type": "host", "normalized_value": name}])["ok"]
    assert record_negative_result(cid, name, "review", "synthetic")["ok"]
"""
    )
    children = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(campaign_env), cid, str(index)]
        )
        for index in range(3)
    ]
    try:
        assert all(child.wait(timeout=10) == 0 for child in children)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
    assert get_evidence_graph_summary(cid)["node_count"] == 24
    assert list_negative_results(cid)["count"] == 24
    events = [
        json.loads(line) for line in Path(paths["audit_jsonl"]).read_text().splitlines()
    ]
    assert sum(event["tool"] == "record_negative_result" for event in events) == 24


def test_integrity_reader_waits_for_sidecar_publication(campaign_env, monkeypatch):
    cid, paths = setup_campaign()
    artifact = Path(paths["evidence"]) / "synthetic.bin"
    write_sidecar = safeio._write_integrity_metadata
    partial = threading.Event()
    continue_write = threading.Event()
    reader_started = threading.Event()

    def pause(*args):
        partial.set()
        assert continue_write.wait(timeout=3)
        return write_sidecar(*args)

    def verify():
        reader_started.set()
        return verify_campaign_artifacts(cid)

    monkeypatch.setattr(safeio, "_write_integrity_metadata", pause)
    with ThreadPoolExecutor(2) as workers:
        writing = workers.submit(
            safeio.write_artifact_bytes, cid, "test", artifact, b"synthetic"
        )
        try:
            assert partial.wait(timeout=3)
            reading = workers.submit(verify)
            assert reader_started.wait(timeout=3)
            assert not reading.done()
        finally:
            continue_write.set()
        assert writing.result(timeout=3)["sha256"] == safeio.sha256_bytes(b"synthetic")
        outcome = reading.result(timeout=3)
    assert outcome["ok"] and outcome["counts"]["verified"] == 1


def test_terminated_artifact_writer_is_detected_and_explicit_retry_recovers(
    campaign_env,
):
    cid, paths = setup_campaign()
    artifact = Path(paths["evidence"]) / "synthetic.bin"
    script = (
        PROCESS_SETUP
        + """
from recon import safeio
def terminate(*args):
    os._exit(73)
safeio._write_integrity_metadata = terminate
safeio.write_artifact_bytes(cid, "test", Path(sys.argv[3]), b"interrupted")
"""
    )
    child = subprocess.run(
        [sys.executable, "-c", script, str(campaign_env), cid, str(artifact)],
        timeout=10,
        check=False,
    )
    assert child.returncode == 73
    result = verify_campaign_artifacts(cid)
    assert not result["ok"]
    assert result["interrupted_artifacts"] == ["evidence/synthetic.bin"]
    assert not result["verified_artifacts"]
    safeio.write_artifact_bytes(cid, "retry", artifact, b"replacement")
    assert verify_campaign_artifacts(cid)["ok"]


def test_archive_waits_for_reauthorization(campaign_env, monkeypatch):
    cid, _ = setup_campaign()
    policy = get_scope_policy_summary()["policy_fingerprint"]
    from recon import campaigns

    save = campaigns._write_json
    writing = threading.Event()
    release = threading.Event()
    archive_started = threading.Event()

    def pause(path, payload):
        if payload.get("scope_binding") and payload.get("status") != "archived":
            writing.set()
            assert release.wait(timeout=3)
        return save(path, payload)

    def archive():
        archive_started.set()
        return archive_campaign(cid)

    monkeypatch.setattr(campaigns, "_write_json", pause)
    with ThreadPoolExecutor(2) as workers:
        reauthorization = workers.submit(
            reauthorize_campaign, cid, "https://example.com/new", policy
        )
        try:
            assert writing.wait(timeout=3)
            archival = workers.submit(archive)
            assert archive_started.wait(timeout=3)
            assert not archival.done()
        finally:
            release.set()
        assert reauthorization.result(timeout=3)["ok"]
        assert archival.result(timeout=3)["ok"]
    archived = get_archived_campaign(cid)["campaign"]
    assert archived["scope_binding"]["anchor"] == "https://example.com/new"
    assert not reauthorize_campaign(cid, "https://example.com/", policy)["ok"]


def test_lock_timeout_and_release_on_exception(campaign_env, monkeypatch):
    cid, _ = setup_campaign()
    monkeypatch.setattr(campaign_lock, "LOCK_TIMEOUT", 0.04)
    with pytest.raises(RuntimeError), campaign_lock.campaign_storage_lock():
        with ThreadPoolExecutor(1) as workers:
            denied = workers.submit(list_negative_results, cid).result(timeout=3)
        assert denied["error_code"] == "campaign_storage_unavailable"
        assert "busy" in denied["error"]
        raise RuntimeError("synthetic failure")
    assert list_negative_results(cid)["ok"]


def test_symlink_lock_is_rejected_without_opening_target(campaign_env, tmp_path):
    path = tmp_path / "unrelated"
    path.write_bytes(b"preserve")
    (tmp_path / campaign_lock.LOCK_NAME).symlink_to(path)
    result = create_campaign("Synthetic audit", "example.com")
    assert result["error_code"] == "campaign_storage_unavailable"
    assert path.read_bytes() == b"preserve"
    assert not campaign_env.exists()


def test_unsupported_mount_never_runs_campaign_operation(campaign_env, monkeypatch):
    def unavailable(fd):
        raise campaign_lock.CampaignLockError("Unsupported synthetic mount.")

    monkeypatch.setattr(campaign_lock, "_check_mount", unavailable)
    assert (
        create_campaign("Synthetic audit", "example.com")["error_code"]
        == "campaign_storage_unavailable"
    )
    assert not campaign_env.exists()


def test_interrupted_jsonl_tail_recovery_preserves_history(campaign_env):
    cid, paths = setup_campaign()
    assert record_negative_result(cid, "example.com", "review", "first")["ok"]
    audit = Path(paths["audit_jsonl"])
    memory = Path(paths["negative_results_jsonl"])
    history = {path: path.read_bytes() for path in (audit, memory)}
    for path in history:
        with path.open("ab") as file:
            file.write(b'{"incomplete":')
    assert list_negative_results(cid)["count"] == 1
    assert record_negative_result(cid, "example.com", "review", "second")["ok"]
    assert [record["result"] for record in list_negative_results(cid)["results"]] == [
        "first",
        "second",
    ]
    for path, original in history.items():
        data = path.read_bytes()
        assert data.startswith(original)
        assert b"incomplete" not in data
        assert all(json.loads(line) for line in data.splitlines())


def test_audit_symlink_prevents_campaign_dispatch(campaign_env, tmp_path, monkeypatch):
    from recon.workflow import fetch_headers_for_campaign

    cid, paths = setup_campaign()
    audit = Path(paths["audit_jsonl"])
    retained = tmp_path / "retained.log"
    audit.rename(retained)
    audit.symlink_to(retained)
    before = retained.read_bytes()
    import httpx

    calls = []
    monkeypatch.setattr(
        "recon.http_fetch._client",
        lambda: httpx.Client(
            transport=httpx.MockTransport(lambda request: calls.append(request))
        ),
    )
    result = fetch_headers_for_campaign(cid, "https://example.com/")
    assert not result["ok"]
    assert result["result"]["error_code"] == "audit_unavailable"
    assert calls == []
    assert retained.read_bytes() == before
    assert not write_audit_event(cid, "test")["ok"]


def test_native_policy_path_fallback_rejects_reparse_point(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace

    from recon.policy_io import PolicyFileError, reject_path_links

    junction = tmp_path / "synthetic-junction"
    junction.mkdir()
    original = Path.lstat

    def native_info(path):
        if path == junction:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return original(path)

    monkeypatch.setattr(Path, "lstat", native_info)
    with pytest.raises(PolicyFileError):
        reject_path_links(junction / "unopened.json")
