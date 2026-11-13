"""Read a Checkov JSON report (`checkov -f plan.json -o json`). Only failed checks are used."""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class ScanFinding:
    check_id: str
    check_name: str
    resource: str
    severity: str | None = None

    def to_dict(self) -> dict:
        return {"tool": "checkov", "check_id": self.check_id, "check_name": self.check_name,
                "resource": self.resource, "severity": self.severity}


def parse_checkov(data) -> list[ScanFinding]:
    """Checkov prints one object per framework, or a list of them when several ran."""
    reports = data if isinstance(data, list) else [data]
    out: list[ScanFinding] = []
    seen = set()
    for rep in reports:
        if not isinstance(rep, dict):
            continue
        for chk in (rep.get("results") or {}).get("failed_checks") or []:
            f = ScanFinding(check_id=str(chk.get("check_id", "?")),
                            check_name=str(chk.get("check_name", "")),
                            resource=str(chk.get("resource", "?")),
                            severity=chk.get("severity"))
            key = (f.check_id, f.resource)
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out


def load_checkov(path: str) -> list[ScanFinding]:
    with open(path, encoding="utf-8") as f:
        return parse_checkov(json.load(f))


def render_findings(findings: list[ScanFinding]) -> str:
    return "\n".join(f"checkov {f.check_id} FAILED on {f.resource}: {f.check_name}" for f in findings)
