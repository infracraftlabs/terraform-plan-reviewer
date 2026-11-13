import json

from conftest import CHECKOV, DEMO, PLANS, RECORDED
from tfreview.cli import main

REC = str(RECORDED / "01-demo-response.json")


def run(capsys, *args):
    code = main([str(a) for a in args])
    return code, capsys.readouterr()


def test_recorded_demo_produces_expected_markdown(capsys):
    code, cap = run(capsys, DEMO, "--checkov", CHECKOV, "--recorded", REC)
    out = cap.out
    assert code == 0
    assert out.startswith("## Terraform plan review (advisory)")
    assert "Plan: **0** to create, **2** to update, **1** to replace, **0** to destroy." in out
    assert "| high | replace | `module.database.aws_db_instance.main` |" in out
    assert "| `CKV_AWS_24` | `aws_security_group.web` |" in out
    assert "### Explanation (recorded model response)" in out
    assert "1. module.database.aws\\_db\\_instance.main will be destroyed and re-created" in out
    assert "(confidence: high)" in out
    assert "   - plan: `identifier: \"app-db\" -> \"app-db-v2\" # forces replacement`" in out
    assert "\\[model-only, no rule or scanner match\\] aws\\_instance.app user data" in out
    assert "engine_version" not in out  # invented risk dropped
    assert "Risks dropped for unverifiable evidence: 1" in out
    assert "Redacted before any model call: aws-access-key 1, email 1, key-value-secret 1, sensitive 2" in out
    assert "root cause" not in out.lower()
    for secret in ["fake-db-pass", "Sup3rS3cretValue", "AKIAABCDEFGHIJKLMNOP"]:
        assert secret not in out


def test_json_output(capsys):
    code, cap = run(capsys, DEMO, "--checkov", CHECKOV, "--recorded", REC, "--json")
    data = json.loads(cap.out)
    assert data["mode"] == "recorded" and data["tool"] == "tfreview"
    assert data["change_counts"]["replace"] == 1
    assert data["dropped_causes"] == 1
    assert len(data["finding"]["likely_causes"]) == 3
    assert {h["rule"] for h in data["rule_hits"]} == {"replace", "protection-off", "open-ingress"}


def test_quote_from_missing_scanner_report_is_dropped(capsys):
    _, cap = run(capsys, DEMO, "--recorded", REC, "--json")
    assert json.loads(cap.out)["dropped_causes"] == 2  # SG risk cites checkov, but no report was given


def test_rules_only_mode(capsys):
    code, cap = run(capsys, DEMO, "--rules-only")
    assert code == 0 and "### Summary (rules only, no model used)" in cap.out
    assert "Mode: rules-only" in cap.out


def test_falls_back_to_rules_only_when_no_model(capsys):
    code, cap = run(capsys, PLANS / "05-harmless.plan.json", "--host", "http://127.0.0.1:9")
    assert code == 0 and "using rules-only mode" in cap.err
    assert "No deterministic rule matched." in cap.out


def test_show_payload_and_output_file(capsys, tmp_path):
    code, cap = run(capsys, DEMO, "--show-payload")
    assert "===== plan-changes =====" in cap.out and "fake-db-pass" not in cap.out
    out = tmp_path / "review.md"
    run(capsys, DEMO, "--rules-only", "-o", out)
    assert out.read_text().startswith("## Terraform plan review")


def test_bad_input_exits_2(capsys, tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    code, cap = run(capsys, p)
    assert code == 2 and "format_version" in cap.err


def test_replay_of_the_real_qwen3_run(capsys):
    """The raw answer saved from the real demo run (examples/demo-output.md), replayed offline."""
    rec = RECORDED / "01-qwen3-8b-response.json"
    _, cap = run(capsys, DEMO, "--checkov", CHECKOV, "--recorded", rec, "--json")
    data = json.loads(cap.out)
    assert data["dropped_causes"] == 0 and len(data["finding"]["likely_causes"]) == 5
