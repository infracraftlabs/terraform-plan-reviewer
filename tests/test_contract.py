from tfreview.opscore.contract import Cause, Evidence, Finding, verify_evidence
from tfreview.plan import load_plan
from tfreview.review import build_inputs, cap_confidence, evidence_text, split_evidence
from tfreview.rules import run_rules

from conftest import DEMO


def _setup():
    plan = load_plan(str(DEMO))
    hits = run_rules(plan)
    inputs, _ = build_inputs(plan, hits, [])
    return plan, hits, inputs


def test_invented_evidence_is_dropped():
    _, _, inputs = _setup()
    f = Finding(summary="s", likely_causes=[
        Cause(cause="real", confidence="high", evidence=[Evidence(source="plan", quote="deletion_protection: true -> false")]),
        Cause(cause="invented", confidence="high", evidence=[Evidence(source="plan", quote='engine_version: "15.7" -> "16.4"')]),
    ])
    kept, dropped = verify_evidence(split_evidence(f), evidence_text(inputs))
    assert [c.cause for c in kept.likely_causes] == ["real"] and dropped == 1


def test_rule_hit_quote_is_replaced_by_the_plan_lines_it_matched():
    _, hits, inputs = _setup()
    rule_line = inputs["rule-hits"].splitlines()[0]
    f = Finding(summary="s", likely_causes=[Cause(cause="x", confidence="high",
                                                   evidence=[Evidence(source="plan", quote=rule_line)])])
    kept, dropped = verify_evidence(split_evidence(f, hits), evidence_text(inputs))
    assert dropped == 0
    assert [e.quote for e in kept.likely_causes[0].evidence] == hits[0].evidence
    # without the rule hits (or with an altered rule line) it is not evidence
    assert verify_evidence(split_evidence(f), evidence_text(inputs))[1] == 1
    forged = rule_line.replace("port 22", "port 22 and the database is public")
    f2 = Finding(summary="s", likely_causes=[Cause(cause="x", confidence="high",
                                                    evidence=[Evidence(source="plan", quote=forged)])])
    assert verify_evidence(split_evidence(f2, hits), evidence_text(inputs))[1] == 1


def test_multiline_quotes_are_checked_line_by_line():
    _, _, inputs = _setup()
    good = "resource: aws_security_group.web\nchanged:\ningress[1].cidr_blocks[0]: (none) -> \"0.0.0.0/0\""
    bad = "resource: aws_security_group.web\ningress[1].cidr_blocks[0]: (none) -> \"192.0.2.0/24\""
    f = Finding(summary="s", likely_causes=[
        Cause(cause="good", confidence="high", evidence=[Evidence(source="plan", quote=good)]),
        Cause(cause="bad", confidence="high", evidence=[Evidence(source="plan", quote=bad)]),
    ])
    kept, dropped = verify_evidence(split_evidence(f), evidence_text(inputs))
    assert [c.cause for c in kept.likely_causes] == ["good"] and dropped == 1
    assert len(kept.likely_causes[0].evidence) == 2  # "changed:" skipped


def test_model_only_risks_are_capped_and_labelled():
    plan, hits, inputs = _setup()
    f = Finding(summary="s", likely_causes=[
        Cause(cause="db", confidence="high", evidence=[Evidence(source="plan", quote="deletion_protection: true -> false")]),
        Cause(cause="tags", confidence="high", evidence=[Evidence(source="plan", quote="resource: aws_instance.app")]),
    ])
    out = cap_confidence(f, plan, hits, [], inputs)
    assert out.likely_causes[0].confidence == "high" and out.likely_causes[0].cause == "db"
    assert out.likely_causes[1].confidence == "medium"
    assert out.likely_causes[1].cause.startswith("[model-only")
