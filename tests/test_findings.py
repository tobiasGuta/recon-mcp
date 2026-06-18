from pathlib import Path

from recon.campaigns import create_campaign, get_campaign_paths
from recon.findings import (
    HALLUCINATION,
    NEEDS_MANUAL_VALIDATION,
    REPORT_CANDIDATE,
    VALIDATED,
    create_finding_candidate,
    get_finding,
    list_findings,
    promote_finding,
    reject_finding,
)


def _campaign(campaign_env):
    return create_campaign("Demo", "example.com")["campaign_id"]


def test_candidate_starts_in_hallucinations(campaign_env):
    campaign_id = _campaign(campaign_env)

    result = create_finding_candidate(campaign_id, {"title": "Possible issue", "target": "https://example.com"})

    assert result["ok"] is True
    assert result["finding"]["status"] == HALLUCINATION
    assert Path(result["path"]).parent.name == "hallucinations"
    assert list_findings(campaign_id, HALLUCINATION)["count"] == 1


def test_invalid_promotion_is_rejected(campaign_env):
    campaign_id = _campaign(campaign_env)
    finding = create_finding_candidate(campaign_id, {"title": "Possible issue"})["finding"]

    result = promote_finding(campaign_id, finding["finding_id"], VALIDATED, "not enough proof")

    assert result["ok"] is False
    assert "invalid promotion" in result["error"].lower()


def test_valid_promotion_moves_file(campaign_env):
    campaign_id = _campaign(campaign_env)
    finding = create_finding_candidate(campaign_id, {"title": "Possible issue"})["finding"]

    result = promote_finding(campaign_id, finding["finding_id"], NEEDS_MANUAL_VALIDATION, "human will validate")

    assert result["ok"] is True
    assert result["finding"]["status"] == NEEDS_MANUAL_VALIDATION
    assert Path(result["path"]).parent.name == "needs_manual_validation"
    assert get_finding(campaign_id, finding["finding_id"])["finding"]["status"] == NEEDS_MANUAL_VALIDATION


def test_rejection_works_from_any_status(campaign_env):
    campaign_id = _campaign(campaign_env)
    finding = create_finding_candidate(campaign_id, {"title": "False lead"})["finding"]

    result = reject_finding(campaign_id, finding["finding_id"], "manual review rejected it")

    assert result["ok"] is True
    assert result["finding"]["status"] == "rejected"
    assert Path(result["path"]).parent.name == "rejected"


def test_report_candidate_requires_all_gates(campaign_env):
    campaign_id = _campaign(campaign_env)
    finding = create_finding_candidate(campaign_id, {"title": "Validated issue"})["finding"]
    promote_finding(campaign_id, finding["finding_id"], NEEDS_MANUAL_VALIDATION, "manual validation started")
    promote_finding(campaign_id, finding["finding_id"], VALIDATED, "reproduced")

    missing = promote_finding(campaign_id, finding["finding_id"], REPORT_CANDIDATE, "ready?")
    assert missing["ok"] is False

    ready = promote_finding(
        campaign_id,
        finding["finding_id"],
        REPORT_CANDIDATE,
        "all gates satisfied",
        gate_updates={
            "scope_confirmed": True,
            "evidence_saved": True,
            "reproduced_manually": True,
            "impact_proven": True,
            "safe_non_destructive": True,
            "report_ready": True,
        },
    )
    assert ready["ok"] is True
    assert ready["finding"]["status"] == REPORT_CANDIDATE


def test_finding_path_traversal_is_blocked(campaign_env):
    campaign_id = _campaign(campaign_env)

    result = get_finding(campaign_id, "../outside")

    assert result["ok"] is False
    assert "unsafe" in result["error"].lower()
