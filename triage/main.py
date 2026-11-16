"""Command-line entry point."""

import argparse
import sys
from collections import Counter
from decimal import Decimal

from botocore.exceptions import EndpointConnectionError

from triage import config, ingest, rules, store
from triage.models import DataIssue, Finding


def print_summary(usage_records: list[dict], findings: list[Finding], issues: list[DataIssue], report_date: str | None = None) -> None:
    report_date = report_date or (findings[0].analysis_date if findings else "unknown")
    affected = len({finding.resource_id for finding in findings})
    counts = Counter(f.severity for f in findings)
    savings_by_resource = {}
    for finding in findings:
        if finding.projected_monthly_savings_usd is not None:
            savings_by_resource[finding.resource_id] = max(
                savings_by_resource.get(finding.resource_id, Decimal("0")),
                finding.projected_monthly_savings_usd,
            )
    total_savings = sum(savings_by_resource.values(), Decimal("0"))

    print(f"CostObserver triage report for {report_date}")
    print()
    print(f"Resources analyzed : {len(usage_records)}")
    print(f"Resources affected : {affected}")
    print(
        "Findings           : "
        f"CRITICAL {counts.get('CRITICAL', 0)} | "
        f"HIGH {counts.get('HIGH', 0)} | MEDIUM {counts.get('MEDIUM', 0)}"
    )
    print(f"Projected monthly avoidable cost: ${total_savings:.2f}")
    print("  (estimate, assuming current daily rates continue and owners approve the change)")

    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    ordered = sorted(findings, key=lambda f: (priority.get(f.severity, 99), f.resource_id, f.rule_id))
    if ordered:
        print()
        print("Needs attention first")
        for finding in ordered:
            print(f"  [{finding.severity}] {finding.resource_id}   {finding.rule_id}")
            if finding.rule_id == "UNATTACHED_VOLUME":
                print(
                    f"             Unattached for {finding.evidence['days_unattached']} days at "
                    f"${finding.evidence['daily_cost_usd']}/day. Confirm with the owner before deleting."
                )
                print(f"             Projected saving: ${finding.projected_monthly_savings_usd:.2f}/month")
            elif finding.rule_id == "PUBLIC_DATABASE":
                print(
                    f"             Port {finding.evidence['database_port']} is open to 0.0.0.0/0. "
                    "Restrict access to approved sources."
                )
            else:
                print(
                    f"             Daily cost ${finding.evidence['daily_cost_usd']} vs 7-day average "
                    f"${finding.evidence['avg_daily_cost_7d_usd']} while port "
                    f"{finding.evidence['database_port']} is open to 0.0.0.0/0."
                )
                print("             Investigate the cost increase and restrict access.")

    if issues:
        print()
        print("Could not fully check")
        for issue in issues:
            print(f"  {issue.resource_id}  {issue.issue}  {issue.detail}")


def run(report_date: str, s3, dynamodb) -> None:
    report = ingest.load_usage_report(s3, config.USAGE_BUCKET, config.usage_key(report_date))
    records = report["records"]
    metadata = ingest.load_metadata(
        dynamodb.Table(config.METADATA_TABLE),
        [record["resource_id"] for record in records],
    )
    findings, issues = rules.evaluate(records, metadata, report_date)
    store.save_findings(dynamodb.Table(config.FINDINGS_TABLE), findings)
    print_summary(records, findings, issues, report_date)


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate cloud cost with resource configuration.")
    parser.add_argument("--date", required=True, help="report date, for example 2026-10-20")
    args = parser.parse_args()
    try:
        run(args.date, config.s3_client(), config.dynamodb_resource())
    except EndpointConnectionError:
        print(f"Could not reach the local emulator at {config.ENDPOINT_URL}. Is moto_server running?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
