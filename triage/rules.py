"""Detection rules. Conditions follow the exercise README exactly."""

from datetime import date
from decimal import Decimal, InvalidOperation

from triage.models import (
    DataIssue, Finding, SEVERITY_BY_RULE, UNATTACHED_VOLUME,
    PUBLIC_DATABASE, EXPOSED_DATABASE_COST_SPIKE,
)


def _decimal(value):
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def check_unattached_volume(usage: dict, metadata: dict, report_date: str) -> Finding | None:
    if usage.get("resource_type") != "ebs_volume":
        return None
    state = metadata.get("attachment_state")
    if state is None:
        return None
    if state != "unattached":
        return None

    detached = metadata.get("unattached_since")
    retention = metadata.get("retention_required")
    cost = _decimal(usage.get("daily_cost_usd"))
    if detached is None or retention is None or cost is None:
        return None
    try:
        days = (date.fromisoformat(report_date) - date.fromisoformat(str(detached))).days
    except ValueError:
        return None

    if days < 7 or days < 0 or cost <= 0 or retention is not False:
        return None

    savings = (cost * Decimal("30")).quantize(Decimal("0.01"))
    return Finding(
        resource_id=usage["resource_id"],
        rule_id=UNATTACHED_VOLUME,
        severity=SEVERITY_BY_RULE[UNATTACHED_VOLUME],
        analysis_date=report_date,
        recommended_action="Confirm with the owner that this volume is no longer needed before deleting it.",
        evidence={
            "daily_cost_usd": cost,
            "days_unattached": days,
            "retention_required": False,
        },
        projected_monthly_savings_usd=savings,
    )


def check_public_database(usage: dict, metadata: dict, report_date: str) -> Finding | None:
    if usage.get("resource_type") != "rds_database":
        return None
    database_port = metadata.get("database_port")
    inbound_rules = metadata.get("inbound_rules")
    if database_port is None or inbound_rules is None:
        return None

    matching = [
        rule for rule in inbound_rules
        if rule.get("port") == database_port and rule.get("cidr") == "0.0.0.0/0"
    ]
    if not matching:
        return None

    return Finding(
        resource_id=usage["resource_id"],
        rule_id=PUBLIC_DATABASE,
        severity=SEVERITY_BY_RULE[PUBLIC_DATABASE],
        analysis_date=report_date,
        recommended_action="Restrict database access to approved network ranges and verify the intended access path.",
        evidence={"database_port": database_port, "exposing_rules": matching},
        projected_monthly_savings_usd=None,
    )


def check_cost_spike(usage: dict, metadata: dict, report_date: str) -> Finding | None:
    if usage.get("resource_type") != "rds_database":
        return None
    # Rule C is explicitly conditional on Rule B.
    if check_public_database(usage, metadata, report_date) is None:
        return None

    baseline = _decimal(usage.get("avg_daily_cost_7d_usd"))
    cost = _decimal(usage.get("daily_cost_usd"))
    if baseline is None or baseline <= 0 or cost is None or cost <= baseline * Decimal("2"):
        return None

    return Finding(
        resource_id=usage["resource_id"],
        rule_id=EXPOSED_DATABASE_COST_SPIKE,
        severity=SEVERITY_BY_RULE[EXPOSED_DATABASE_COST_SPIKE],
        analysis_date=report_date,
        recommended_action="Investigate the cost increase and review database activity; the increase alone does not prove an attack.",
        evidence={
            "daily_cost_usd": cost,
            "avg_daily_cost_7d_usd": baseline,
            "multiple_of_baseline": (cost / baseline).quantize(Decimal("0.01")),
            "database_port": metadata["database_port"],
            "public_cidr": "0.0.0.0/0",
        },
        projected_monthly_savings_usd=None,
    )


def evaluate(usage_records: list[dict], metadata_by_id: dict[str, dict], report_date: str):
    findings: list[Finding] = []
    issues: list[DataIssue] = []

    for usage in usage_records:
        resource_id = usage.get("resource_id", "unknown")
        resource_type = usage.get("resource_type")
        metadata = metadata_by_id.get(resource_id)
        if metadata is None:
            issues.append(DataIssue(resource_id, "MISSING_METADATA", "No metadata found for this resource."))
            continue

        if resource_type == "ebs_volume":
            if metadata.get("attachment_state") is None:
                issues.append(DataIssue(resource_id, "MISSING_FIELD", "Cannot check volume rule: attachment_state is missing."))
                continue
            if metadata["attachment_state"] == "unattached":
                missing = [field for field in ("unattached_since", "retention_required") if metadata.get(field) is None]
                if missing:
                    issues.append(DataIssue(resource_id, "MISSING_FIELD", f"Cannot check volume rule: missing {', '.join(missing)}."))
                    continue
                if usage.get("daily_cost_usd") is None:
                    issues.append(DataIssue(resource_id, "MISSING_FIELD", "Cannot check volume rule: daily_cost_usd is missing."))
                    continue
            finding = check_unattached_volume(usage, metadata, report_date)
            if finding:
                findings.append(finding)

        elif resource_type == "rds_database":
            missing = [field for field in ("database_port", "inbound_rules") if metadata.get(field) is None]
            if missing:
                issues.append(DataIssue(resource_id, "MISSING_FIELD", f"Cannot check database exposure: missing {', '.join(missing)}."))
                continue
            public_finding = check_public_database(usage, metadata, report_date)
            if public_finding:
                findings.append(public_finding)
                if _decimal(usage.get("avg_daily_cost_7d_usd")) in (None, Decimal("0")):
                    issues.append(DataIssue(resource_id, "BASELINE_UNAVAILABLE", "Cannot check exposed database cost spike because the 7-day average is missing or zero."))
                elif usage.get("daily_cost_usd") is None:
                    issues.append(DataIssue(resource_id, "MISSING_FIELD", "Cannot check database cost spike: daily_cost_usd is missing."))
                else:
                    spike = check_cost_spike(usage, metadata, report_date)
                    if spike:
                        findings.append(spike)

    return findings, issues
