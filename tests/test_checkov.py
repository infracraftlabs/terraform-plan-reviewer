import json

from conftest import CHECKOV
from tfreview.checkov import load_checkov, parse_checkov


def test_real_checkov_report_is_parsed():
    findings = load_checkov(str(CHECKOV))
    ids = {(f.check_id, f.resource) for f in findings}
    assert ("CKV_AWS_24", "aws_security_group.web") in ids
    assert ("CKV_AWS_293", "module.database.aws_db_instance.main") in ids
    assert len(findings) == 9


def test_list_form_and_duplicates():
    rep = json.loads(CHECKOV.read_text())
    assert len(parse_checkov([rep, rep])) == 9
    assert parse_checkov({"results": {}}) == []
