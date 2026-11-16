"""Persistence tests without requiring a live AWS service."""

from decimal import Decimal

from triage.models import Finding, UNATTACHED_VOLUME
from triage.store import save_findings


class MemoryTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[Item["finding_id"]] = Item


def test_saving_same_finding_twice_does_not_duplicate():
    table = MemoryTable()
    finding = Finding(
        resource_id="vol-1",
        rule_id=UNATTACHED_VOLUME,
        severity="MEDIUM",
        analysis_date="2026-10-20",
        recommended_action="Confirm with owner.",
        evidence={"daily_cost_usd": Decimal("2.00")},
        projected_monthly_savings_usd=Decimal("60.00"),
    )
    assert save_findings(table, [finding]) == 1
    assert save_findings(table, [finding]) == 1
    assert len(table.items) == 1
    assert table.items[finding.finding_id]["projected_monthly_savings_usd"] == Decimal("60.00")
