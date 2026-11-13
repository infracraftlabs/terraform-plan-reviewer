"""Deterministic risk rules. They run before any model and are the fallback when no model is reachable.

Each hit names a resource address and, where possible, the exact attribute line from the
rendered change table, so the model (and the reader) can quote it as evidence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .plan import UNKNOWN, Plan, ResourceChange, changed_attributes, flatten

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

STATEFUL = re.compile(
    r"(db_instance|rds_cluster$|_database$|sql_database|_sql_server$|^aws_s3_bucket$|storage_bucket$|"
    r"dynamodb_table$|ebs_volume$|efs_file_system$|_disk$|elasticache_(cluster|replication_group)$|"
    r"redshift_cluster$|kms_key$|storage_account$|bigtable|spanner|cosmosdb|opensearch_domain$|"
    r"elasticsearch_domain$|docdb_cluster$|neptune_cluster$|fsx_|backup_vault$|secretsmanager_secret$|"
    r"filestore_instance$|redis_instance$|key_vault$)"
)
NETWORK_RULE_TYPES = re.compile(r"(security_group|firewall|network_acl|security_rule|network_security)")
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
BROAD_ROLES = {"roles/owner", "roles/editor"}


@dataclass
class RuleHit:
    rule: str
    severity: str
    address: str
    detail: str
    path: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "address": self.address,
                "path": self.path, "detail": self.detail, "evidence": self.evidence}


def _truthy(v: Any) -> bool:
    return v not in (None, False, "", "false", 0, [], {})


def _last(path: str) -> str:
    """Attribute name at the end of a path: 'ingress[0].cidr_blocks[0]' -> 'cidr_blocks'."""
    return re.sub(r"(\[\d+\])+$", "", path).split(".")[-1]


def _path_str(parts: list) -> str:
    s = ""
    for part in parts:
        s += f"[{part}]" if isinstance(part, int) else (f".{part}" if s else str(part))
    return s


class _Ctx:
    """Per-resource view: flattened before/after and the rendered attribute lines."""

    def __init__(self, rc: ResourceChange):
        self.rc = rc
        self.before = flatten(rc.before) if isinstance(rc.before, (dict, list)) else {}
        self.after = flatten(rc.after) if isinstance(rc.after, (dict, list)) else {}
        self.rows = {p: f"{p}: {b} -> {a}" for p, b, a in changed_attributes(rc)}
        self.head = f"resource: {rc.address}"
        self.hits: list[RuleHit] = []

    def hit(self, rule: str, severity: str, detail: str, path: str | None = None, extra: str | None = None):
        ev = [self.head]
        if path and path in self.rows:
            ev.append(self.rows[path])
            if extra and extra in self.rows[path]:
                ev.append(extra)
        self.hits.append(RuleHit(rule, severity, self.rc.address, detail, path, ev))

    def changed_to(self, path: str) -> bool:
        return path in self.rows and not self.rows[path].endswith(f"-> {UNKNOWN}")


def _rule_destroy(c: _Ctx) -> None:
    rc = c.rc
    stateful = bool(STATEFUL.search(rc.type))
    if rc.kind == "delete":
        c.hits.append(RuleHit("destroy", "high" if stateful else "medium", rc.address,
                              "Resource will be destroyed" + (" (stateful: data loss risk)" if stateful else ""),
                              None, [c.head, "action: delete (delete)"]))
    elif rc.kind == "replace":
        forcing = [".".join(str(x) for x in p) for p in rc.replace_paths]
        detail = "Resource will be replaced (destroyed and re-created)"
        if stateful:
            detail += "; stateful: data loss risk unless data is migrated"
        if forcing:
            detail += f"; forced by: {', '.join(forcing)}"
        ev = [c.head, f"action: replace ({', '.join(rc.actions)})"]
        forced = {_path_str(p) for p in rc.replace_paths}
        ev += [line for path, line in c.rows.items() if path in forced]
        c.hits.append(RuleHit("replace", "high" if stateful else "medium", rc.address, detail, None, ev[:3]))


def _rule_open_ingress(c: _Ctx) -> None:
    rc = c.rc
    if rc.kind not in ("create", "update", "replace") or not NETWORK_RULE_TYPES.search(rc.type):
        return
    direction = str(c.after.get("type", c.after.get("direction", ""))).lower()
    if direction in ("egress",):
        return
    for path, value in c.after.items():
        if not isinstance(value, str) or value not in OPEN_CIDRS or "egress" in path.lower() or c.before.get(path) == value:
            continue
        if not c.changed_to(path):
            continue
        ports = ""
        base = path.split(".cidr")[0].split(".ipv6")[0] if "." in path else ""
        fp = c.after.get(f"{base}.from_port" if base else "from_port")
        tp = c.after.get(f"{base}.to_port" if base else "to_port")
        if fp is not None:
            ports = f" on port {fp}" if fp == tp else f" on ports {fp}-{tp}"
        c.hit("open-ingress", "high", f"Network rule opens ingress to {value} (the whole internet){ports}", path)


def _policy_statements(text: Any) -> list[dict]:
    if not isinstance(text, str) or "Statement" not in text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    st = doc.get("Statement", []) if isinstance(doc, dict) else []
    return [s for s in (st if isinstance(st, list) else [st]) if isinstance(s, dict)]


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


def _policy_issues(text: Any) -> set[tuple[str, str, str]]:
    """(rule, severity, fragment) for wildcard grants in an IAM-style policy document."""
    issues = set()
    for s in _policy_statements(text):
        if s.get("Effect", "Allow") != "Allow":
            continue
        frag = lambda k: json.dumps({k: s[k]}, separators=(",", ":"))[1:-1]  # noqa: E731
        actions = [str(a) for a in _as_list(s.get("Action", []))]
        if "NotAction" in s:
            issues.add(("iam-wildcard", "high", frag("NotAction")))
        if any(a in ("*", "*:*") for a in actions):
            issues.add(("iam-wildcard", "high", frag("Action")))
        elif any(a.endswith(":*") for a in actions):
            issues.add(("iam-wildcard", "medium", frag("Action")))
        if "*" in [str(r) for r in _as_list(s.get("Resource", []))] and actions:
            issues.add(("iam-wildcard", "medium", frag("Resource")))
        principal = s.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))):
            issues.add(("public-access", "high", frag("Principal")))
    return issues


def _rule_iam(c: _Ctx) -> None:
    rc = c.rc
    if rc.kind not in ("create", "update", "replace"):
        return
    for path, value in c.after.items():
        if path not in c.rows:
            continue
        new = _policy_issues(value) - _policy_issues(c.before.get(path))
        for rule, sev, fragment in sorted(new):
            what = "Policy grants public access" if rule == "public-access" else "IAM policy widened with a wildcard"
            c.hit(rule, sev, f"{what}: {fragment}", path, extra=fragment)
        key = _last(path)
        if key in ("policy_arn",) and isinstance(value, str) and value.endswith("/AdministratorAccess"):
            c.hit("iam-wildcard", "high", "Administrator access policy attached", path)
        if key == "role" and isinstance(value, str) and value in BROAD_ROLES and "iam" in rc.type:
            c.hit("iam-wildcard", "high", f"Broad project role granted: {value}", path)
        if key in ("member", "members") or re.search(r"members\[\d+\]$", path):
            if isinstance(value, str) and value in PUBLIC_MEMBERS:
                c.hit("public-access", "high", f"Grants access to {value}", path)


def _rule_encryption(c: _Ctx) -> None:
    rc = c.rc
    if rc.kind == "delete" and "encryption" in rc.type:
        c.hits.append(RuleHit("encryption-off", "high", rc.address,
                              "Encryption configuration resource will be destroyed", None,
                              [c.head, "action: delete (delete)"]))
        return
    if rc.kind not in ("create", "update", "replace"):
        return
    for path, line in c.rows.items():
        key = _last(path).lower()
        before, after = c.before.get(path), c.after.get(path)
        if line.endswith(f"-> {UNKNOWN}"):
            continue
        is_flag = "encrypt" in key or ("encryption" in rc.type and key == "enabled")
        if is_flag and after in (False, "false", "Disabled", "NONE") and (rc.kind == "create" or _truthy(before)):
            c.hit("encryption-off", "high" if rc.kind != "create" else "medium",
                  "Encryption turned off" if rc.kind != "create" else "Created with encryption disabled", path)
        elif key in ("kms_key_id", "kms_key_arn", "kms_master_key_id") and _truthy(before) and not _truthy(after):
            c.hit("encryption-off", "medium", "Customer-managed encryption key removed", path)
        elif key == "sse_algorithm" and _truthy(before) and not _truthy(after):
            c.hit("encryption-off", "high", "Server-side encryption removed", path)


def _rule_protection(c: _Ctx) -> None:
    if c.rc.kind not in ("update", "replace"):
        return
    for path in c.rows:
        key = _last(path).lower()
        was, after = c.before.get(path), c.after.get(path)
        if key in ("deletion_protection", "termination_protection", "deletion_protection_enabled") \
                and after is False and was is True:
            c.hit("protection-off", "high", "Deletion protection turned off", path)
        elif key == "disable_api_termination" and was is True and after is False:
            c.hit("protection-off", "medium", "Termination protection turned off", path)
        elif key == "skip_final_snapshot" and after is True and was is False:
            c.hit("protection-off", "medium", "Final snapshot will be skipped on delete", path)
        elif key == "force_destroy" and after is True and was is not True:
            c.hit("protection-off", "medium", "Bucket can be destroyed with its contents (force_destroy)", path)


def _rule_public(c: _Ctx) -> None:
    rc = c.rc
    if rc.kind == "delete" and rc.type.endswith("public_access_block"):
        c.hits.append(RuleHit("public-access", "high", rc.address,
                              "Public access block will be removed", None, [c.head, "action: delete (delete)"]))
        return
    if rc.kind not in ("create", "update", "replace"):
        return
    for path in c.rows:
        key = _last(path).lower()
        before, after = c.before.get(path), c.after.get(path)
        if rc.type.endswith("public_access_block") and key.startswith(("block_public", "ignore_public", "restrict_public")) \
                and after is False and (before is True or rc.kind == "create"):
            c.hit("public-access", "high", f"Public access block weakened: {key} = false", path)
        elif key == "acl" and isinstance(after, str) and after in PUBLIC_ACLS:
            c.hit("public-access", "high", f"Bucket ACL set to {after}", path)
        elif key == "publicly_accessible" and after is True and before is not True:
            c.hit("public-access", "high", "Resource becomes publicly accessible", path)


RULES = [_rule_destroy, _rule_open_ingress, _rule_iam, _rule_encryption, _rule_protection, _rule_public]


def run_rules(plan: Plan) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for rc in plan.changed:
        ctx = _Ctx(rc)
        for rule in RULES:
            rule(ctx)
        hits.extend(ctx.hits)
    return sorted(hits, key=lambda h: (SEVERITY_ORDER[h.severity], h.address, h.rule))


def flagged_paths(hits: list[RuleHit]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for h in hits:
        if h.path:
            out.setdefault(h.address, set()).add(h.path)
    return out


def render_hits(hits: list[RuleHit]) -> str:
    if not hits:
        return "No deterministic rule matched."
    return "\n".join(f"R{i}: [{h.severity}] {h.rule} on {h.address}"
                     f"{' at ' + h.path if h.path else ''}: {h.detail}" for i, h in enumerate(hits, 1))
