# Demo output

- Date: 2026-11-14
- Model: qwen3:8b (local, Ollama; 8.2B, Q4_K_M)
- Input files: `examples/plans/01-db-replace-sg-open.plan.json` (synthetic plan), `examples/checkov/01-db-replace-sg-open.checkov.json` (Checkov 3.4.4 run on that plan; absolute paths replaced with `/work`; the report's guideline URLs were removed afterwards and do not affect the review)
- Command: `tfreview examples/plans/01-db-replace-sg-open.plan.json --checkov examples/checkov/01-db-replace-sg-open.checkov.json --save-response examples/recorded/01-qwen3-8b-response.json`
- The model's raw answer (before the evidence check) is in `examples/recorded/01-qwen3-8b-response.json`.

One recorded run; language-model output varies.

Exact terminal output (stdout and stderr):

````text
## Terraform plan review (advisory)

Plan: **0** to create, **2** to update, **1** to replace, **0** to destroy.

### Flagged by rules

| Severity | Rule | Resource | Detail |
|---|---|---|---|
| high | open-ingress | `aws_security_group.web` `ingress[1].cidr_blocks[0]` | Network rule opens ingress to 0.0.0.0/0 (the whole internet) on port 22 |
| high | protection-off | `module.database.aws_db_instance.main` `deletion_protection` | Deletion protection turned off |
| high | replace | `module.database.aws_db_instance.main` | Resource will be replaced (destroyed and re-created); stateful: data loss risk unless data is migrated; forced by: identifier |
| medium | protection-off | `module.database.aws_db_instance.main` `skip_final_snapshot` | Final snapshot will be skipped on delete |

### Scanner findings (Checkov)

| Check | Resource | Name |
|---|---|---|
| `CKV_AWS_24` | `aws_security_group.web` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 |
| `CKV_AWS_382` | `aws_security_group.web` | Ensure no security groups allow egress from 0.0.0.0:0 to port -1 |
| `CKV_AWS_161` | `module.database.aws_db_instance.main` | Ensure RDS database has IAM authentication enabled |
| `CKV_AWS_293` | `module.database.aws_db_instance.main` | Ensure that AWS database instances have deletion protection enabled |
| `CKV_AWS_353` | `module.database.aws_db_instance.main` | Ensure that RDS instances have performance insights enabled |
| `CKV_AWS_157` | `module.database.aws_db_instance.main` | Ensure that RDS instances have Multi-AZ enabled |
| `CKV_AWS_129` | `module.database.aws_db_instance.main` | Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled |
| `CKV_AWS_226` | `module.database.aws_db_instance.main` | Ensure DB instance gets all minor upgrades automatically |
| `CKV_AWS_118` | `module.database.aws_db_instance.main` | Ensure that enhanced monitoring is enabled for Amazon RDS instances |

### Explanation (AI, evidence-checked)

The plan replaces a database instance, updates a security group to allow internet access on port 22, and updates tags on an EC2 instance. A reviewer should focus on the database replacement and the open SSH access in the security group first.

**Risks to review**

1. module.database.aws\_db\_instance.main: Deletion protection is disabled, risking accidental data loss during replacement (confidence: high)
   - plan: `resource: module.database.aws_db_instance.main`
   - plan: `deletion_protection: true -> false`
   - checkov: `checkov CKV_AWS_293 FAILED on module.database.aws_db_instance.main: Ensure that AWS database instances have deletion protection enabled`
2. module.database.aws\_db\_instance.main: The database will be replaced, risking data loss unless migration is planned (confidence: high)
   - plan: `resource: module.database.aws_db_instance.main`
   - plan: `action: replace (delete, create)`
   - plan: `identifier: "app-db" -> "app-db-v2"`
3. aws\_security\_group.web: Ingress allows access from 0.0.0.0/0 on port 22, exposing the system to potential attacks (confidence: high)
   - plan: `resource: aws_security_group.web`
   - plan: `ingress[1].cidr_blocks[0]: (none) -> "0.0.0.0/0"`
   - checkov: `checkov CKV_AWS_24 FAILED on aws_security_group.web: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22`
4. module.database.aws\_db\_instance.main: Skip final snapshot is enabled, which may result in data loss if not properly backed up (confidence: high)
   - plan: `resource: module.database.aws_db_instance.main`
   - plan: `skip_final_snapshot: false -> true`
5. module.database.aws\_db\_instance.main: Multiple security and compliance checks failed, indicating potential vulnerabilities and misconfigurations (confidence: high)
   - checkov: `checkov CKV_AWS_161 FAILED on module.database.aws_db_instance.main: Ensure RDS database has IAM authentication enabled`
   - checkov: `checkov CKV_AWS_293 FAILED on module.database.aws_db_instance.main: Ensure that AWS database instances have deletion protection enabled`
   - checkov: `checkov CKV_AWS_353 FAILED on module.database.aws_db_instance.main: Ensure that RDS instances have performance insights enabled`
   - checkov: `checkov CKV_AWS_157 FAILED on module.database.aws_db_instance.main: Ensure that RDS instances have Multi-AZ enabled`
   - checkov: `checkov CKV_AWS_129 FAILED on module.database.aws_db_instance.main: Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled`
   - checkov: `checkov CKV_AWS_226 FAILED on module.database.aws_db_instance.main: Ensure DB instance gets all minor upgrades automatically`
   - checkov: `checkov CKV_AWS_118 FAILED on module.database.aws_db_instance.main: Ensure that enhanced monitoring is enabled for Amazon RDS instances`

**Questions and checks for a person** (this tool runs nothing)

- Is a data migration or a moved block planned for module.database.aws\_db\_instance.main?
- Is the open SSH access on aws\_security\_group.web intentional, and is it secured with additional measures?
- Are the failed compliance checks on the database instance critical, and are they being addressed?
- Is the replacement of the database instance necessary, and is there a backup plan in place?
- Is the use of the AWS access key in the tags on aws\_instance.app secure, and is it properly rotated?
- Is the DB\_PASSWORD in the user\_data of aws\_instance.app properly managed and encrypted?

**Suggested change (for the author to consider):** Consider enabling deletion protection for the database instance, securing the SSH access in the security group, and addressing the failed compliance checks to ensure the database is configured securely.

---

Mode: ai | Model: qwen3:8b (local, Ollama) | Redacted before any model call: aws-access-key 1, email 1, key-value-secret 1, sensitive 2 | Risks dropped for unverifiable evidence: 0

_Likely risks, not a guarantee. A person reviews the plan and decides. This tool never runs plan or apply._
````
