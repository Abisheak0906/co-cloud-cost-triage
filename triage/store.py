"""Persist findings to DynamoDB."""

from dataclasses import asdict
from decimal import Decimal

from triage.models import Finding


def _dynamo_safe(value):
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {key: _dynamo_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_dynamo_safe(item) for item in value]
    return value


def save_findings(table, findings: list[Finding]) -> int:
    """Upsert each finding using its deterministic finding_id."""
    written = 0
    for finding in findings:
        item = asdict(finding)
        item["finding_id"] = finding.finding_id
        if item["projected_monthly_savings_usd"] is None:
            del item["projected_monthly_savings_usd"]
        table.put_item(Item=_dynamo_safe(item))
        written += 1
    return written
