# terraform-plan-reviewer (`tfreview`)

`tfreview` reads the JSON form of a Terraform plan (`terraform show -json plan.out`) and, optionally, a Checkov report, and writes a short review that a person can paste into a pull request. Deterministic rules flag the changes reviewers most often miss: destroyed or replaced resources, network rules opened to `0.0.0.0/0`, IAM policies widened with `*`, encryption or deletion protection turned off, and public buckets. A local language model then groups those changes and explains them in plain English, quoting the resource address and attribute for every point. Quotes are checked against the plan text; anything the model cannot back up is dropped. It is part of the [InfraCraft Labs](https://infracraftlabs.com) AI Lab.

## Status

**Prototype.** It works on the demo scenario and the synthetic plans in `examples/`. It is not for production use.

## Quick start

Needs Python 3.12 and, for AI mode, Ollama running locally.

```sh
git clone https://github.com/infracraftlabs/terraform-plan-reviewer && cd terraform-plan-reviewer
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
ollama pull qwen3:8b
.venv/bin/tfreview examples/plans/01-db-replace-sg-open.plan.json --checkov examples/checkov/01-db-replace-sg-open.checkov.json
.venv/bin/tfreview examples/plans/01-db-replace-sg-open.plan.json --rules-only     # no model
.venv/bin/tfreview examples/plans/01-db-replace-sg-open.plan.json --json           # machine-readable
.venv/bin/tfreview examples/plans/01-db-replace-sg-open.plan.json --show-payload   # exactly what the model would see
.venv/bin/pytest
```

On your own stack: `terraform plan -out plan.out && terraform show -json plan.out > plan.json && tfreview plan.json`.
The plan format is documented at [developer.hashicorp.com](https://developer.hashicorp.com/terraform/internals/json-format).

Options: `--model` and `--host` (or `OLLAMA_MODEL`, `OLLAMA_HOST`) choose the local model; `--recorded FILE` replays a saved model answer; `--save-response FILE` keeps the model's raw answer; `-o FILE` writes the report to a file.

## How it works

1. **Read the plan.** Only `resource_changes` is used. `variables`, `prior_state`, `planned_values`, `configuration` and outputs are never read into the review, because they repeat raw values.
2. **Sensitive markers, then redaction.** Every value Terraform marks in `before_sensitive` / `after_sensitive` becomes `[REDACTED:sensitive]`. Then the shared redactor removes secret-looking strings (keys, tokens, `password=` values, emails, private keys, high-entropy strings) from every remaining value. IP addresses and CIDR ranges are kept, because they are the evidence for exposure findings. The report prints how many values were redacted, by kind.
3. **Rules.** A change table is built from the changed attributes only (`before -> after`, `(known after apply)` for unknown values, `# forces replacement` from `replace_paths`). Rules flag: `destroy`, `replace` (high for stateful types such as databases, buckets and volumes), `open-ingress`, `iam-wildcard`, `encryption-off`, `protection-off` and `public-access`. Checkov failed checks are added if a report is given (`checkov -f plan.json -o json`).
4. **Model (AI mode, the default).** The change table, rule hits and scanner lines are sent to a local Ollama model, each wrapped and labelled as untrusted data. The model returns a fixed JSON shape: summary, up to 5 risks with evidence, questions for the author.
5. **Evidence check.** Every quote must appear exactly in the redacted plan or scanner text that was sent. Multi-line quotes are checked line by line; a quoted rule-hit line is replaced by the plan lines that rule matched. A risk with any quote that cannot be found is dropped, and the number dropped is printed. `high` confidence needs a rule or scanner match on the quoted resource; other risks are capped at `medium` and labelled "model-only".
6. **Output.** Markdown for one pull-request comment (rule table first, so the deterministic findings are always visible), or `--json`. If no model is reachable, it says so and falls back to rules-only.

## Security model

- **What it reads:** the plan JSON file and the optional Checkov JSON file you pass. Nothing else.
- **What it sends:** only to the local Ollama HTTP API (by default on this machine, port 11434), and only the redacted change table, rule hits and scanner lines. `--show-payload` prints exactly that.
- **What never happens:** it never runs `terraform`, never calls a cloud API, needs no cloud credentials, never applies, approves or blocks anything, and has no shell or exec path. The model is given no tools.
- **Untrusted input:** resource names, tags and descriptions come from the pull-request author. They are wrapped as data, the comment template is fixed, and model text is escaped so it cannot add links, images or @mentions.
- **Plan files are secrets.** Even with redaction, treat plan files as sensitive. The Checkov docs warn that plan files can contain secrets.
- **GitHub Actions:** [`examples/github-actions/tfreview-pr-comment.yml`](examples/github-actions/tfreview-pr-comment.yml) runs on `pull_request`, reads a committed plan JSON and posts one comment. It needs no cloud credentials. Its only write permission is `pull-requests: write` (plus `contents: read` to check out the code); see [controlling `GITHUB_TOKEN` permissions](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token). Don't run `terraform plan` with real credentials on pull requests from forks; produce the plan in a trusted job.

## Limitations

- Tested only on the 6 synthetic plans in `examples/plans/` and one real plan made with the `null` and `local` providers. No real cloud plans yet.
- Rules are name-based (attribute and resource type names). They know common AWS attributes and a few Google Cloud ones; other providers and custom modules will be missed or misread.
- Set-type blocks (for example `ingress` on `aws_security_group`) are compared by position, so a reordered set can show as changed.
- A sensitive value that changes is not shown as changed (both sides are `[REDACTED:sensitive]`).
- Only the first 30 changed attributes per resource and the first 400 characters of a value are sent; flagged attributes go first.
- `resource_drift`, `output_changes`, `count`/`for_each` expansion details and module intent are not analysed.
- The evidence check proves a quote exists, not that it supports the claim. In the demo run the model grouped unrelated Checkov findings into one risk.
- A small local model can over-report on routine plans; model-only risks are labelled so you can discount them.
- Only Checkov reports are read; Trivy is not supported yet.
- The redactor is pattern-based. It can miss secrets in unusual formats.

## Demo

[`examples/demo-output.md`](examples/demo-output.md) is one real run of `qwen3:8b` on the database-replacement and open-SSH plan. The answers in `examples/recorded/` are used by the offline tests: `01-qwen3-8b-response.json` is the raw answer saved from that run; `01-demo-response.json` and `06-obeys-injection-response.json` are hand-written test inputs (the second simulates a model that followed an injected instruction).

## Licence

MIT. See [LICENSE](LICENSE).
