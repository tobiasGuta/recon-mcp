from recon.planner import generate_manual_test_plan


def test_generate_manual_test_plan_rejects_non_dict_input():
    result = generate_manual_test_plan(None)

    assert result["ok"] is False
    assert "dictionary" in result["error"]
