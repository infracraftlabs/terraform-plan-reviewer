"""Markdown for a pull-request comment. The template is fixed; model text is escaped."""
from __future__ import annotations

import re

from .review import PlanReview

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")


def md(text: str) -> str:
    """Escape Markdown/HTML and break @mentions, so plan or model text can't add links, images or pings."""
    text = " ".join(str(text).split())
    text = _MD_SPECIAL.sub(r"\\\1", text)
    return text.replace("@", "@​")


def code(text: str) -> str:
    """Inline code span that can't be closed early by backticks in the text."""
    text = " ".join(str(text).split()).replace("`", "'")
    return f"`{text}`" if text else "``"


def to_markdown(r: PlanReview) -> str:
    c = r.change_counts
    out = ["## Terraform plan review (advisory)", ""]
    out.append(f"Plan: **{c.get('create', 0)}** to create, **{c.get('update', 0)}** to update, "
               f"**{c.get('replace', 0)}** to replace, **{c.get('delete', 0)}** to destroy.")
    for w in r.warnings:
        out += ["", f"> Warning: {md(w)}"]

    out += ["", "### Flagged by rules", ""]
    if r.rule_hits:
        out += ["| Severity | Rule | Resource | Detail |", "|---|---|---|---|"]
        for h in r.rule_hits:
            where = code(h["address"]) + (f" {code(h['path'])}" if h.get("path") else "")
            out.append(f"| {h['severity']} | {h['rule']} | {where} | {md(h['detail'])} |")
    else:
        out.append("No deterministic rule matched.")

    if r.scanner_findings:
        out += ["", "### Scanner findings (Checkov)", "", "| Check | Resource | Name |", "|---|---|---|"]
        for f in r.scanner_findings:
            out.append(f"| {code(f['check_id'])} | {code(f['resource'])} | {md(f['check_name'])} |")

    title = {"ai": "Explanation (AI, evidence-checked)", "recorded": "Explanation (recorded model response)",
             "rules-only": "Summary (rules only, no model used)"}[r.mode]
    out += ["", f"### {title}", "", md(r.finding.summary)]
    if r.finding.likely_causes:
        out += ["", "**Risks to review**", ""]
        for i, cause in enumerate(r.finding.likely_causes, 1):
            out.append(f"{i}. {md(cause.cause)} (confidence: {cause.confidence})")
            for ev in cause.evidence:
                out.append(f"   - {ev.source}: {code(ev.quote)}")
    if r.finding.next_checks:
        out += ["", "**Questions and checks for a person** (this tool runs nothing)", ""]
        out += [f"- {md(x)}" for x in r.finding.next_checks]
    if r.finding.suggested_change:
        out += ["", f"**Suggested change (for the author to consider):** {md(r.finding.suggested_change)}"]

    red = ", ".join(f"{k} {v}" for k, v in sorted(r.redactions.items())) or "none"
    model = f" | Model: {r.model}" if r.model else ""
    out += ["", "---", "",
            f"Mode: {r.mode}{model} | Redacted before any model call: {red} | "
            f"Risks dropped for unverifiable evidence: {r.dropped_causes}",
            "", f"_{r.note}_", ""]
    return "\n".join(out)
