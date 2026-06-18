from recon.campaigns import create_campaign
from recon.memory import list_negative_results, record_negative_result


def test_negative_results_are_recorded_and_filtered(campaign_env):
    campaign = create_campaign("Demo", "example.com")

    result = record_negative_result(
        campaign["campaign_id"],
        "https://example.com",
        "backup_config_discovery",
        "No exposed backup/config files found.",
        repeat_after="major app change",
    )

    assert result["ok"] is True
    listed = list_negative_results(campaign["campaign_id"])
    assert listed["count"] == 1
    assert listed["results"][0]["check_type"] == "backup_config_discovery"
    assert list_negative_results(campaign["campaign_id"], check_type="other")["count"] == 0
