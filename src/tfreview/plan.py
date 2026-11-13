"""Read `terraform show -json` output and build a compact, redacted change model.

Format reference: https://developer.hashicorp.com/terraform/internals/json-format
Only `resource_changes` is used. `variables`, `prior_state`, `configuration` and
`output_changes` are never read into the change model, so they never reach the model.
Unknown properties are ignored, as the format documentation advises.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .opscore.redact import redact

SENSITIVE = "[REDACTED:sensitive]"
UNKNOWN = "(known after apply)"
ABSENT = "(none)"
MAX_VALUE_CHARS = 400
MAX_LINES_PER_RESOURCE = 30


class PlanError(ValueError):
    pass


@dataclass
class ResourceChange:
    address: str
    type: str
    actions: list[str]
    before: Any
    after: Any
    after_unknown: Any
    replace_paths: list[list[Any]]
    action_reason: str | None = None

    @property
    def kind(self) -> str:
        a = self.actions
        if "delete" in a and "create" in a:
            return "replace"
        if a == ["delete"]:
            return "delete"
        if a == ["create"]:
            return "create"
        if a == ["update"]:
            return "update"
        if a == ["read"]:
            return "read"
        return "no-op"


@dataclass
class Plan:
    format_version: str
    terraform_version: str | None
    errored: bool
    changes: list[ResourceChange]
    redactions: dict[str, int] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        out = {"create": 0, "update": 0, "replace": 0, "delete": 0}
        for c in self.changes:
            if c.kind in out:
                out[c.kind] += 1
        return out

    @property
    def changed(self) -> list[ResourceChange]:
        return [c for c in self.changes if c.kind in ("create", "update", "replace", "delete")]


def _bump(counts: dict[str, int], kind: str, n: int = 1) -> None:
    if n:
        counts[kind] = counts.get(kind, 0) + n


def mask_sensitive(value: Any, marker: Any, counts: dict[str, int]) -> Any:
    """Replace every value marked sensitive (before_sensitive/after_sensitive) with a placeholder.

    The marker mirrors the value's structure: `true` marks a value as sensitive, objects and
    arrays mark their members. A missing marker means not sensitive.
    """
    if marker is True:
        if value is None:
            return None
        _bump(counts, "sensitive")
        return SENSITIVE
    if isinstance(marker, dict) and isinstance(value, dict):
        return {k: mask_sensitive(v, marker.get(k), counts) for k, v in value.items()}
    if isinstance(marker, list) and isinstance(value, list):
        return [mask_sensitive(v, marker[i] if i < len(marker) else None, counts) for i, v in enumerate(value)]
    return value


def _redact_leaf(key: str, value: Any, counts: dict[str, int]) -> Any:
    """Run the shared pattern redactor on one string value, with its attribute name as context.

    Giving the key lets the key/value rule catch e.g. `password = "..."` attributes that a
    provider forgot to mark as sensitive. IP addresses and CIDR ranges are kept: they are the
    evidence for public-exposure findings.
    """
    if not isinstance(value, str) or value == SENSITIVE:
        return value
    prefix = f"{key}="
    out = redact(prefix + value, keep_ips=True)
    for k, n in out.counts.items():
        _bump(counts, k, n)
    text = out.text
    return text[len(prefix):] if text.startswith(prefix) else text


def redact_values(value: Any, counts: dict[str, int], key: str = "value") -> Any:
    if isinstance(value, dict):
        return {k: redact_values(v, counts, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_values(v, counts, key) for v in value]
    return _redact_leaf(key, value, counts)


def parse_plan(data: dict) -> Plan:
    if not isinstance(data, dict) or "format_version" not in data:
        raise PlanError("not a Terraform plan JSON (missing format_version); use `terraform show -json plan.out`")
    major = str(data["format_version"]).split(".")[0]
    if major != "1":
        raise PlanError(f"unsupported plan format_version {data['format_version']!r} (expected 1.x)")
    counts: dict[str, int] = {}
    changes: list[ResourceChange] = []
    for rc in data.get("resource_changes") or []:
        ch = rc.get("change") or {}
        if rc.get("mode") == "data":
            continue
        before = mask_sensitive(ch.get("before"), ch.get("before_sensitive"), counts)
        after = mask_sensitive(ch.get("after"), ch.get("after_sensitive"), counts)
        changes.append(ResourceChange(
            address=str(rc.get("address", "?")),
            type=str(rc.get("type", "?")),
            actions=list(ch.get("actions") or ["no-op"]),
            before=redact_values(before, counts),
            after=redact_values(after, counts),
            after_unknown=ch.get("after_unknown") or {},
            replace_paths=list(ch.get("replace_paths") or []),
            action_reason=rc.get("action_reason"),
        ))
    return Plan(
        format_version=str(data["format_version"]),
        terraform_version=data.get("terraform_version"),
        errored=bool(data.get("errored", False)),
        changes=changes,
        redactions=counts,
    )


def load_plan(path: str) -> Plan:
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise PlanError(f"{path}: not valid JSON ({e})") from e
    return parse_plan(data)


# ---------- flattening and rendering ----------

def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """{"a": {"b": [1]}} -> {"a.b[0]": 1}. Empty containers are kept as leaves."""
    out: dict[str, Any] = {}
    if isinstance(value, dict) and value:
        for k, v in value.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(value, list) and value:
        for i, v in enumerate(value):
            out.update(flatten(v, f"{prefix}[{i}]"))
    elif prefix:
        out[prefix] = value
    return out


def unknown_paths(after_unknown: Any) -> set[str]:
    return {p for p, v in flatten(after_unknown).items() if v is True}


def fmt(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, str):
        if value == SENSITIVE:
            return value
        s = value.strip()
        if s[:1] in "{[":
            try:
                s = json.dumps(json.loads(s), separators=(",", ":"))
            except ValueError:
                pass
        s = s.replace("\r", "").replace("\n", "\\n")
        if len(s) > MAX_VALUE_CHARS:
            s = s[:MAX_VALUE_CHARS] + "...(truncated)"
        return f'"{s}"'
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return json.dumps(value)


def changed_attributes(rc: ResourceChange) -> list[tuple[str, str, str]]:
    """(path, before, after) for attributes that differ. Creates list set attributes."""
    before = flatten(rc.before) if rc.before is not None else {}
    after = flatten(rc.after) if rc.after is not None else {}
    unknown = unknown_paths(rc.after_unknown)
    rows: list[tuple[str, str, str]] = []
    if rc.kind == "delete":
        return rows
    paths = sorted(set(before) | set(after) | unknown)
    for p in paths:
        b = fmt(before[p]) if p in before else ABSENT
        a = UNKNOWN if p in unknown else (fmt(after[p]) if p in after else ABSENT)
        if a in ("null", ABSENT, "[]", "{}") and (rc.kind == "create" or b == ABSENT):
            continue  # empty values on new resources or new nested blocks are noise
        if b != a:
            rows.append((p, b, a))
    return rows


def _replace_path_strs(rc: ResourceChange) -> set[str]:
    out = set()
    for path in rc.replace_paths:
        s = ""
        for part in path:
            s += f"[{part}]" if isinstance(part, int) else (f".{part}" if s else str(part))
        out.add(s)
    return out


def render_change(rc: ResourceChange, priority: set[str] | None = None) -> str:
    lines = [f"resource: {rc.address}", f"type: {rc.type}",
             f"action: {rc.kind} ({', '.join(rc.actions)})"]
    if rc.action_reason:
        lines.append(f"action_reason: {rc.action_reason}")
    forces = _replace_path_strs(rc)
    priority = (priority or set()) | forces
    rows = changed_attributes(rc)
    rows.sort(key=lambda r: r[0] not in priority)  # flagged attributes first, then alphabetical
    if rc.kind == "delete":
        lines.append("changed: resource will be destroyed")
    elif rows:
        lines.append("changed:")
        for p, b, a in rows[:MAX_LINES_PER_RESOURCE]:
            tag = "  # forces replacement" if p in forces else ""
            lines.append(f"  {p}: {b} -> {a}{tag}")
        if len(rows) > MAX_LINES_PER_RESOURCE:
            lines.append(f"  ... {len(rows) - MAX_LINES_PER_RESOURCE} more attributes not shown")
    return "\n".join(lines)


def render_changes(plan: Plan, priority: dict[str, set[str]] | None = None) -> str:
    """The redacted change table sent to the model. Only changed resources and attributes."""
    priority = priority or {}
    return "\n\n".join(render_change(c, priority.get(c.address)) for c in plan.changed)
