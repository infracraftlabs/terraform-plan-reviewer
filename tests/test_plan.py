import json

import pytest

from conftest import DEMO, PLANS
from tfreview.plan import SENSITIVE, PlanError, load_plan, mask_sensitive, parse_plan, render_changes


def test_demo_plan_counts_and_kinds():
    plan = load_plan(str(DEMO))
    assert plan.counts == {"create": 0, "update": 2, "replace": 1, "delete": 0}
    kinds = {c.address: c.kind for c in plan.changes}
    assert kinds["module.database.aws_db_instance.main"] == "replace"


@pytest.mark.parametrize("actions,kind", [
    (["create"], "create"), (["update"], "update"), (["delete"], "delete"),
    (["delete", "create"], "replace"), (["create", "delete"], "replace"),
    (["no-op"], "no-op"), (["read"], "read"),
])
def test_every_documented_action_combination(actions, kind):
    plan = parse_plan({"format_version": "1.2", "resource_changes": [
        {"address": "null_resource.x", "type": "null_resource", "change": {"actions": actions}}]})
    assert plan.changes[0].kind == kind


def test_nested_sensitive_markers_are_masked():
    counts = {}
    value = {"a": "visible", "b": {"c": "hide-me"}, "d": ["x", "hide-too"]}
    marker = {"b": {"c": True}, "d": [False, True]}
    out = mask_sensitive(value, marker, counts)
    assert out == {"a": "visible", "b": {"c": SENSITIVE}, "d": ["x", SENSITIVE]}
    assert counts == {"sensitive": 2}
    assert mask_sensitive("all", True, {}) == SENSITIVE


def test_unknown_values_and_replacement_are_shown():
    text = render_changes(load_plan(str(DEMO)))
    assert 'identifier: "app-db" -> "app-db-v2"  # forces replacement' in text
    assert "endpoint: " in text and "-> (known after apply)" in text


def test_variables_and_planned_values_are_never_read():
    text = render_changes(load_plan(str(DEMO)))
    assert "fake-db-pass" not in text  # present in variables/planned_values/before/after of the file


def test_real_terraform_output_parses():
    """07 was produced by terraform 1.17 with the null and local providers (examples/stacks/null-local)."""
    path = PLANS / "07-real-null-local.plan.json"
    raw = path.read_text()
    assert "fake-token-not-real-0000" in raw  # the plan file itself holds the raw value
    plan = load_plan(str(path))
    assert plan.counts["create"] == 3
    text = render_changes(plan)
    assert "fake-token-not-real" not in text
    assert f"content: (none) -> {SENSITIVE}" in text
    assert plan.redactions["sensitive"] >= 1


def test_rejects_non_plan_and_wrong_version(tmp_path):
    with pytest.raises(PlanError):
        parse_plan({"resource_changes": []})
    with pytest.raises(PlanError):
        parse_plan({"format_version": "2.0"})
    bad = tmp_path / "x.json"
    bad.write_text("not json")
    with pytest.raises(PlanError):
        load_plan(str(bad))


def test_unknown_properties_are_ignored():
    data = json.loads(DEMO.read_text())
    data["some_future_field"] = {"x": 1}
    data["resource_changes"][0]["change"]["new_marker"] = True
    assert parse_plan(data).counts["replace"] == 1
