import pytest

from conftest import PLANS
from tfreview.plan import load_plan
from tfreview.rules import run_rules

EXPECTED = {
    "01-db-replace-sg-open.plan.json": {
        ("replace", "module.database.aws_db_instance.main", "high"),
        ("protection-off", "module.database.aws_db_instance.main", "high"),
        ("protection-off", "module.database.aws_db_instance.main", "medium"),
        ("open-ingress", "aws_security_group.web", "high"),
    },
    "02-iam-wildcard.plan.json": {
        ("iam-wildcard", "aws_iam_policy.deploy", "high"),
        ("iam-wildcard", "aws_iam_policy.deploy", "medium"),
        ("iam-wildcard", "aws_iam_role_policy_attachment.ci_admin", "high"),
        ("iam-wildcard", "aws_iam_role_policy.reader", "medium"),
    },
    "03-encryption-off.plan.json": {
        ("encryption-off", "aws_ebs_encryption_by_default.this", "high"),
        ("protection-off", "aws_rds_cluster.reporting", "high"),
        ("encryption-off", "aws_s3_bucket_server_side_encryption_configuration.logs", "high"),
        ("destroy", "aws_s3_bucket_server_side_encryption_configuration.logs", "medium"),
    },
    "04-public-bucket.plan.json": {
        ("public-access", "aws_s3_bucket_public_access_block.assets", "high"),
        ("public-access", "aws_s3_bucket_acl.assets", "high"),
        ("public-access", "aws_s3_bucket_policy.assets", "high"),
    },
    "05-harmless.plan.json": set(),
    "06-tag-injection.plan.json": {("open-ingress", "aws_security_group.admin", "high")},
    "07-real-null-local.plan.json": set(),
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_is_classified(name):
    hits = run_rules(load_plan(str(PLANS / name)))
    assert {(h.rule, h.address, h.severity) for h in hits} == EXPECTED[name]


def test_open_ingress_names_the_port_and_existing_egress_is_ignored():
    hits = run_rules(load_plan(str(PLANS / "01-db-replace-sg-open.plan.json")))
    sg = [h for h in hits if h.rule == "open-ingress"]
    assert len(sg) == 1 and "port 22" in sg[0].detail and sg[0].path == "ingress[1].cidr_blocks[0]"


def test_every_hit_quotes_lines_from_the_change_table():
    from tfreview.plan import render_changes
    from tfreview.rules import flagged_paths
    for name in EXPECTED:
        plan = load_plan(str(PLANS / name))
        hits = run_rules(plan)
        text = render_changes(plan, flagged_paths(hits))
        for h in hits:
            assert h.evidence and all(q in text for q in h.evidence), (name, h)
