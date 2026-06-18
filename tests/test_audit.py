import json
from pathlib import Path

from recon.audit import write_audit_event
from recon.campaigns import create_campaign, get_campaign_paths


def test_audit_appends_jsonl(campaign_env):
    campaign = create_campaign("Demo", "example.com")

    first = write_audit_event(campaign["campaign_id"], "tool_one", ok=True)
    second = write_audit_event(campaign["campaign_id"], "tool_two", target="https://example.com", ok=False, warnings=["note"])

    assert first["ok"] is True
    assert second["ok"] is True
    audit_path = Path(get_campaign_paths(campaign["campaign_id"])["paths"]["audit_jsonl"])
    lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert [line["tool"] for line in lines] == ["tool_one", "tool_two"]
    assert lines[1]["warnings"] == ["note"]


def test_audit_blocks_unsafe_campaign_id(campaign_env):
    result = write_audit_event("../outside", "tool")

    assert result["ok"] is False
    assert "audit not written" in result["warnings"][0].lower()
