from pathlib import Path

from recon.campaigns import create_campaign
from recon.findings import NEEDS_MANUAL_VALIDATION, REPORT_CANDIDATE, VALIDATED, create_finding_candidate, promote_finding
from recon.memory import record_negative_result
from recon.reports import generate_campaign_markdown_summary, generate_report_candidate_markdown
from recon.workflow import extract_endpoints_for_campaign


def test_campaign_summary_is_generated(campaign_env):
    campaign = create_campaign("Demo", "example.com")
    campaign_id = campaign["campaign_id"]
    extract_endpoints_for_campaign(campaign_id, "fetch('/api/v1/users'); fetch('/assets/app.css')", source_type="raw")
    record_negative_result(campaign_id, "https://example.com", "backup_config_discovery", "No backups found.")
    create_finding_candidate(campaign_id, {"title": "Possible issue"})

    result = generate_campaign_markdown_summary(campaign_id)

    assert result["ok"] is True
    assert Path(result["path"]).exists()
    assert "Top Endpoint Candidates" in result["summary"]
    assert "Negative Results" in result["summary"]


def test_report_candidate_markdown_requires_report_candidate(campaign_env):
    campaign_id = create_campaign("Demo", "example.com")["campaign_id"]
    finding = create_finding_candidate(campaign_id, {"title": "Possible issue"})["finding"]

    blocked = generate_report_candidate_markdown(campaign_id, finding["finding_id"])
    assert blocked["ok"] is False

    promote_finding(campaign_id, finding["finding_id"], NEEDS_MANUAL_VALIDATION, "manual validation")
    promote_finding(campaign_id, finding["finding_id"], VALIDATED, "reproduced")
    promote_finding(
        campaign_id,
        finding["finding_id"],
        REPORT_CANDIDATE,
        "ready",
        gate_updates={
            "scope_confirmed": True,
            "evidence_saved": True,
            "reproduced_manually": True,
            "impact_proven": True,
            "safe_non_destructive": True,
            "report_ready": True,
        },
    )

    result = generate_report_candidate_markdown(campaign_id, finding["finding_id"])
    assert result["ok"] is True
    assert Path(result["path"]).exists()
    assert "Remaining Human Review" in result["markdown"]
