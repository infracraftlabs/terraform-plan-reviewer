"""One real run against a local model. Skipped by default: pytest -m live"""
import pytest

from conftest import CHECKOV, DEMO
from tfreview.checkov import load_checkov
from tfreview.opscore.llm import Ollama
from tfreview.plan import load_plan
from tfreview.review import review
from tfreview.rules import run_rules


@pytest.mark.live
def test_live_demo():
    model = Ollama()
    if not model.available():
        pytest.skip("no local model")
    plan = load_plan(str(DEMO))
    report = review(plan, run_rules(plan), load_checkov(str(CHECKOV)), provider=model, mode="ai")
    assert report.mode == "ai"
    assert report.finding.summary
    for cause in report.finding.likely_causes:
        assert cause.evidence
