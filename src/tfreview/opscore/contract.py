"""The output contract shared by every AI Lab assistant.

The model must return this shape. Before anything is shown to a person, every quoted
evidence line is checked against the input: a cause whose evidence can't be found is
dropped, so made-up quotes never reach the reader.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Confidence = Literal["low", "medium", "high"]


class Evidence(BaseModel):
    source: str = Field(description="Where the line came from, e.g. 'log', 'events', 'plan'.")
    quote: str = Field(description="An exact line or fragment copied from the input.")


class Cause(BaseModel):
    cause: str = Field(description="A likely cause in one plain sentence.")
    confidence: Confidence
    evidence: list[Evidence] = Field(min_length=1)


class Finding(BaseModel):
    summary: str = Field(description="Two or three plain sentences for a busy engineer.")
    likely_causes: list[Cause] = Field(max_length=5)
    next_checks: list[str] = Field(default_factory=list, max_length=6,
                                   description="Commands or checks for a person to run. Never run automatically.")
    suggested_change: str | None = Field(default=None, description="Optional change, as text for a pull request.")


class Report(BaseModel):
    """What the tool prints: the checked finding plus how it was produced."""
    finding: Finding
    mode: Literal["ai", "rules-only", "recorded"]
    model: str | None = None
    redactions: dict[str, int] = Field(default_factory=dict)
    dropped_causes: int = 0
    note: str = "Likely causes, not a guaranteed root cause. A person decides."


def _norm(s: str) -> str:
    return " ".join(s.split()).lower()


def verify_evidence(finding: Finding, inputs: str) -> tuple[Finding, int]:
    """Keep only causes whose every evidence quote appears in the (redacted) input."""
    haystack = _norm(inputs)
    kept: list[Cause] = []
    for cause in finding.likely_causes:
        quotes = [e for e in cause.evidence if len(_norm(e.quote)) >= 8 and _norm(e.quote) in haystack]
        if quotes and len(quotes) == len(cause.evidence):
            kept.append(cause)
    dropped = len(finding.likely_causes) - len(kept)
    return finding.model_copy(update={"likely_causes": kept}), dropped


def json_schema() -> dict:
    """JSON schema for the model's structured output."""
    return Finding.model_json_schema()
