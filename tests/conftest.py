from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLANS = ROOT / "examples" / "plans"
CHECKOV = ROOT / "examples" / "checkov" / "01-db-replace-sg-open.checkov.json"
RECORDED = ROOT / "examples" / "recorded"
DEMO = PLANS / "01-db-replace-sg-open.plan.json"


@pytest.fixture
def plan_path():
    return lambda name: str(PLANS / name)
