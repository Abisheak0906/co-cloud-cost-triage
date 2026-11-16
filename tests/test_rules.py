"""Rule tests covering positive, negative, boundary and missing-data cases."""

from decimal import Decimal

from triage import rules
from triage.models import UNATTACHED_VOLUME, PUBLIC_DATABASE, EXPOSED_DATABASE_COST_SPIKE

DATE = "2026-10-20"


def volume(days=7, cost="2.00", retention=False, state="unattached"):
    from datetime import date, timedelta
    detached = (date.fromisoformat(DATE) - timedelta(days=days)).isoformat()
    return (
        {"resource_id": "vol-test", "resource_type": "ebs_volume", "daily_cost_usd": Decimal(cost)},
        {"resource_id": "vol-test", "attachment_state": state, "unattached_since": detached, "retention_required": retention},
    )


def database(cost="90", baseline="30", port=5432, cidr="0.0.0.0/0", rule_port=5432):
    return (
        {"resource_id": "db-test", "resource_type": "rds_database", "daily_cost_usd": Decimal(cost),
         "avg_daily_cost_7d_usd": Decimal(baseline)},
        {"resource_id": "db-test", "database_port": port, "inbound_rules": [{"port": rule_port, "cidr": cidr}]},
    )


def test_volume_exactly_seven_days_is_flagged():
    usage, meta = volume(days=7)
    finding = rules.check_unattached_volume(usage, meta, DATE)
    assert finding.rule_id == UNATTACHED_VOLUME
    assert finding.projected_monthly_savings_usd == Decimal("60.00")


def test_volume_six_days_is_not_flagged():
    usage, meta = volume(days=6)
    assert rules.check_unattached_volume(usage, meta, DATE) is None


def test_volume_requires_explicit_false_and_positive_cost():
    usage, meta = volume(retention=True)
    assert rules.check_unattached_volume(usage, meta, DATE) is None
    usage, meta = volume(cost="0")
    assert rules.check_unattached_volume(usage, meta, DATE) is None


def test_public_database_requires_database_port_and_anywhere_cidr():
    usage, meta = database()
    assert rules.check_public_database(usage, meta, DATE).rule_id == PUBLIC_DATABASE
    usage, meta = database(rule_port=443)
    assert rules.check_public_database(usage, meta, DATE) is None
    usage, meta = database(cidr="10.0.0.0/16")
    assert rules.check_public_database(usage, meta, DATE) is None


def test_cost_spike_must_be_more_than_two_times():
    usage, meta = database(cost="60", baseline="30")
    assert rules.check_cost_spike(usage, meta, DATE) is None
    usage, meta = database(cost="60.01", baseline="30")
    assert rules.check_cost_spike(usage, meta, DATE).rule_id == EXPOSED_DATABASE_COST_SPIKE


def test_cost_spike_only_applies_to_public_database():
    usage, meta = database(cost="100", baseline="30", cidr="10.0.0.0/16")
    assert rules.check_cost_spike(usage, meta, DATE) is None


def test_evaluate_reports_missing_metadata_and_baseline():
    usage, meta = database(baseline="0")
    records = [usage, {"resource_id": "missing", "resource_type": "ebs_volume"}]
    findings, issues = rules.evaluate(records, {"db-test": meta}, DATE)
    assert [f.rule_id for f in findings] == [PUBLIC_DATABASE]
    assert {issue.issue for issue in issues} == {"MISSING_METADATA", "BASELINE_UNAVAILABLE"}


def test_evaluate_reports_missing_volume_fields():
    usage, _ = volume()
    findings, issues = rules.evaluate([usage], {"vol-test": {"resource_id": "vol-test", "attachment_state": "unattached"}}, DATE)
    assert findings == []
    assert issues[0].issue == "MISSING_FIELD"


def test_database_missing_metadata_fields_is_reported():
    usage, _ = database()
    findings, issues = rules.evaluate([usage], {"db-test": {"resource_id": "db-test"}}, DATE)
    assert findings == []
    assert len(issues) == 1
    assert issues[0].issue == "MISSING_FIELD"
