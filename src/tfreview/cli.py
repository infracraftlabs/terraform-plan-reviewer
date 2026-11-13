"""tfreview: explain the risky changes in a Terraform plan JSON, for a pull-request comment.

Reads files only. Never runs terraform, never calls a cloud API, never posts anything.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checkov import load_checkov
from .opscore.llm import DEFAULT_HOST, DEFAULT_MODEL, ModelUnavailable, Ollama, Recorded
from .plan import PlanError, load_plan
from .render import to_markdown
from .review import build_inputs, review
from .rules import run_rules


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tfreview", description=__doc__.splitlines()[0])
    p.add_argument("plan", help="plan JSON from `terraform show -json plan.out`")
    p.add_argument("--checkov", metavar="FILE", help="optional Checkov JSON report (`checkov -f plan.json -o json`)")
    p.add_argument("--json", action="store_true", help="print the JSON report instead of Markdown")
    p.add_argument("--rules-only", action="store_true", help="do not call a model")
    p.add_argument("--recorded", metavar="FILE", help="replay a recorded model response (tests, offline demo)")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default {DEFAULT_MODEL}, env OLLAMA_MODEL)")
    p.add_argument("--host", default=DEFAULT_HOST, help="Ollama URL (env OLLAMA_HOST)")
    p.add_argument("--show-payload", action="store_true",
                   help="print the exact redacted data that would be sent to the model, then exit")
    p.add_argument("--save-response", metavar="FILE", help="save the model's raw answer (before the evidence check)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to a file instead of stdout")
    p.add_argument("--version", action="version", version=f"tfreview {__version__}")
    a = p.parse_args(argv)

    try:
        plan = load_plan(a.plan)
        findings = load_checkov(a.checkov) if a.checkov else []
    except (OSError, PlanError, json.JSONDecodeError) as e:
        print(f"tfreview: {e}", file=sys.stderr)
        return 2

    hits = run_rules(plan)
    if a.show_payload:
        inputs, counts = build_inputs(plan, hits, findings)
        for k, v in inputs.items():
            print(f"===== {k} =====\n{v}\n")
        print(f"===== redactions =====\n{json.dumps(counts, sort_keys=True)}")
        return 0

    provider, mode = None, "rules-only"
    if a.recorded:
        provider, mode = Recorded(Path(a.recorded)), "recorded"
    elif not a.rules_only:
        ollama = Ollama(model=a.model, host=a.host)
        if ollama.available():
            provider, mode = ollama, "ai"
        else:
            print(f"tfreview: model {a.model} not reachable at {a.host}; using rules-only mode", file=sys.stderr)

    try:
        report = review(plan, hits, findings, provider=provider, mode=mode, save_response=a.save_response)
    except (ModelUnavailable, ValueError) as e:
        print(f"tfreview: model call failed ({str(e)[:200]}); using rules-only mode", file=sys.stderr)
        report = review(plan, hits, findings, provider=None, mode="rules-only")

    text = report.model_dump_json(indent=2) + "\n" if a.json else to_markdown(report)
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
