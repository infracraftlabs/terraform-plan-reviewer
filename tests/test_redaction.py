"""Planted fake secrets in plan JSON never reach the model request."""
import json

from conftest import CHECKOV, DEMO, PLANS
from tfreview.checkov import load_checkov
from tfreview.opscore import llm
from tfreview.plan import load_plan, parse_plan
from tfreview.review import review
from tfreview.rules import run_rules

# All fake. Planted in examples/plans/01 (sensitive-marked password, user_data, tags) and 07 (real plan).
PLANTED = ["fake-db-pass-0000", "fake-db-pass-0001", "Sup3rS3cretValue", "AKIAABCDEFGHIJKLMNOP",
           "owner@example.com", "fake-token-not-real"]


class _Resp:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": json.dumps({"summary": "ok", "likely_causes": []})}}


def capture_request(monkeypatch, plan_file, checkov=None):
    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent["url"], sent["payload"] = url, json
        return _Resp()

    monkeypatch.setattr(llm.httpx, "post", fake_post)
    plan = load_plan(str(plan_file))
    findings = load_checkov(str(checkov)) if checkov else []
    report = review(plan, run_rules(plan), findings, provider=llm.Ollama(model="test-model"), mode="ai")
    return sent, report


def test_planted_secrets_never_reach_the_model(monkeypatch):
    for plan_file, ck in [(DEMO, CHECKOV), (PLANS / "07-real-null-local.plan.json", None)]:
        sent, report = capture_request(monkeypatch, plan_file, ck)
        body = json.dumps(sent["payload"])
        assert sent["url"].endswith("/api/chat")
        for secret in PLANTED:
            assert secret not in body, (plan_file.name, secret)
        assert report.redactions.get("sensitive", 0) >= 1
    # the real plan's sensitive file content reaches the model only as a placeholder
    assert "content: (none) -> [REDACTED:sensitive]" in body


def test_redaction_counts_are_reported(monkeypatch):
    _, report = capture_request(monkeypatch, DEMO, CHECKOV)
    assert report.redactions == {"aws-access-key": 1, "email": 1, "key-value-secret": 1, "sensitive": 2}


def test_password_attribute_without_sensitive_marker_is_redacted():
    plan = parse_plan({"format_version": "1.2", "resource_changes": [{
        "address": "aws_db_instance.x", "type": "aws_db_instance",
        "change": {"actions": ["create"], "before": None,
                   "after": {"master_password": "NotMarkedButSecret1", "user_data": "token ghp_" + "a" * 36}}}]})
    text = json.dumps(plan.changes[0].after)
    assert "NotMarkedButSecret1" not in text and "ghp_aaaa" not in text


def test_cidrs_are_kept_as_evidence():
    plan = load_plan(str(DEMO))
    sg = next(c for c in plan.changes if c.address == "aws_security_group.web")
    assert sg.after["ingress"][1]["cidr_blocks"] == ["0.0.0.0/0"]
