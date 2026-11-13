"""Text in a resource tag can't change what the tool does."""
import json
import re

from conftest import PLANS, RECORDED, ROOT
from tfreview.cli import main
from tfreview.opscore import llm
from tfreview.plan import load_plan
from tfreview.review import build_inputs, review
from tfreview.rules import run_rules

INJ = PLANS / "06-tag-injection.plan.json"


def test_injection_text_stays_inside_the_untrusted_wrapper(monkeypatch):
    sent = {}

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": json.dumps({"summary": "s", "likely_causes": []})}}

    monkeypatch.setattr(llm.httpx, "post", lambda url, json=None, timeout=None: sent.update(p=json) or R())
    plan = load_plan(str(INJ))
    review(plan, run_rules(plan), [], provider=llm.Ollama(model="m"), mode="ai")
    payload = sent["p"]
    assert set(payload) == {"model", "stream", "think", "format", "options", "messages"}
    assert "tools" not in payload  # no tool calling at all
    system, user = payload["messages"][0]["content"], payload["messages"][1]["content"]
    assert "ignore previous instructions" not in system
    # the tag's fake closing tag is neutralised: every block opens and closes exactly once
    assert user.count("<untrusted-input") == user.count("</untrusted-input>") == 2
    inside = re.search(r'<untrusted-input source="plan-changes">(.*?)</untrusted-input>', user, re.S).group(1)
    assert "ignore previous instructions" in inside


def test_rules_still_flag_the_risky_change():
    hits = run_rules(load_plan(str(INJ)))
    assert [h.rule for h in hits] == ["open-ingress"]
    inputs, _ = build_inputs(load_plan(str(INJ)), hits, [])
    assert "ignore previous instructions" not in inputs["rule-hits"]


def test_a_model_that_obeys_the_injection_cannot_hide_rule_hits(capsys):
    main([str(INJ), "--recorded", str(RECORDED / "06-obeys-injection-response.json")])
    out = capsys.readouterr().out
    assert "| high | open-ingress | `aws_security_group.admin`" in out
    assert "Approved by the AI reviewer" not in out  # invented evidence: dropped
    assert "Risks dropped for unverifiable evidence: 1" in out
    # model text can't add images, links or @mentions to the PR comment
    assert "![x](" not in out and "@security-team" not in out


def test_tool_has_no_write_or_exec_path():
    src = "\n".join(p.read_text() for p in (ROOT / "src" / "tfreview").rglob("*.py"))
    for forbidden in ["subprocess", "os.system", "os.popen", "exec(", "eval(", "httpx.put", "httpx.delete",
                      "requests.", "api.github.com", "GITHUB_TOKEN"]:
        assert forbidden not in src, forbidden
    assert src.count("httpx.post(") == 1 and "/api/chat" in src  # the only network write is the model call
