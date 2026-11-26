from collections import Counter
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.utils import timezone

from alerts.models import SecurityAlert
from detections.models import DetectionRule
from detections.services import _alert_matches, _list_condition
from incidents.models import SecurityIncident
from intelligence.models import ThreatIntelligenceRecord


def _clamp(value, low, high):
    return max(low, min(high, int(value or low)))


def _sample_alert(alert):
    classification = getattr(alert, "classification", None)
    incident_count = SecurityIncident.objects.filter(alert=alert).count()
    return {
        "alert_id": alert.id,
        "external_id": alert.external_id,
        "title": alert.title,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "category": classification.category if classification else "",
        "risk_score": classification.risk_score if classification else 0,
        "incident_count": incident_count,
    }


def _backtest_single(rule, since, limit):
    alerts = list(
        SecurityAlert.objects.filter(organization=rule.organization, received_at__gte=since)
        .select_related("classification")
        .order_by("-received_at")[:limit]
    )
    matches = []
    for alert in alerts:
        if _alert_matches(alert, rule.conditions or {}):
            matches.append(_sample_alert(alert))
    return {"evaluated": len(alerts), "matches": matches}


def _backtest_correlation(rule, since, limit):
    conditions = rule.conditions or {}
    group_by = conditions.get("group_by", "source_ip")
    if group_by not in {"source_ip", "user_identity", "alert_type"}:
        group_by = "source_ip"
    min_count = max(2, int(conditions.get("min_count") or 3))
    window_minutes = max(1, int(conditions.get("window_minutes") or 30))
    min_distinct = int(conditions.get("min_distinct_counterpart") or 0)
    alerts = list(
        SecurityAlert.objects.filter(organization=rule.organization, received_at__gte=since)
        .select_related("classification")
        .order_by("received_at")[:limit]
    )
    groups = {}
    for alert in alerts:
        if not _alert_matches(alert, conditions):
            continue
        value = str(getattr(alert, group_by, "") or "")
        if not value:
            continue
        groups.setdefault(value, []).append(alert)
    matches = []
    for value, grouped in groups.items():
        recent = []
        for alert in grouped:
            recent = [
                item
                for item in recent
                if item.received_at >= alert.received_at - timedelta(minutes=window_minutes)
            ]
            recent.append(alert)
            if len(recent) < min_count:
                continue
            counterpart_field = "user_identity" if group_by == "source_ip" else "source_ip"
            counterparts = {
                getattr(item, counterpart_field, "")
                for item in recent
                if getattr(item, counterpart_field, "")
            }
            if min_distinct and len(counterparts) < min_distinct:
                continue
            matches.append(
                {
                    "group_by": group_by,
                    "value": value,
                    "alert_ids": [item.id for item in recent],
                    "alert_count": len(recent),
                    "counterparts": sorted(counterparts),
                    "detected_at": alert.received_at.isoformat(),
                }
            )
    return {"evaluated": len(alerts), "matches": matches}


def _backtest_threat_intel(rule, since, limit):
    conditions = rule.conditions or {}
    min_confidence = int(conditions.get("min_confidence") or 0)
    source_types = _list_condition(conditions, "source_types")
    records = list(
        ThreatIntelligenceRecord.objects.filter(
            organization=rule.organization, malicious=True, observed_at__gte=since
        )
        .select_related("indicator")
        .order_by("-observed_at")[:limit]
    )
    matches = []
    for record in records:
        if min_confidence and record.confidence < min_confidence:
            continue
        if source_types and record.source_type not in source_types:
            continue
        matches.append(
            {
                "record_id": record.id,
                "indicator": record.indicator.value,
                "indicator_type": record.indicator.indicator_type,
                "source_name": record.source_name,
                "confidence": record.confidence,
                "observed_at": record.observed_at.isoformat(),
            }
        )
    return {"evaluated": len(records), "matches": matches}


def _assess_false_positives(rule, match_rate):
    base = {
        DetectionRule.Severity.LOW: 15,
        DetectionRule.Severity.MEDIUM: 10,
        DetectionRule.Severity.HIGH: 6,
        DetectionRule.Severity.CRITICAL: 3,
    }.get(rule.severity, 10)
    if not (rule.conditions or {}):
        base += 10
    return _clamp(base + round(match_rate * 0.2), 1, 40)


def backtest_rule(rule, lookback_hours=168, limit=1000):
    if not isinstance(rule, DetectionRule):
        raise ValueError("A DetectionRule instance is required.")
    hours = _clamp(lookback_hours, 1, 8760)
    sample_limit = _clamp(limit, 10, 5000)
    since = timezone.now() - timedelta(hours=hours)

    if rule.rule_type == DetectionRule.RuleType.SINGLE:
        result = _backtest_single(rule, since, sample_limit)
    elif rule.rule_type == DetectionRule.RuleType.CORRELATION:
        result = _backtest_correlation(rule, since, sample_limit)
    elif rule.rule_type == DetectionRule.RuleType.THREAT_INTEL:
        result = _backtest_threat_intel(rule, since, sample_limit)
    else:
        result = {"evaluated": 0, "matches": []}

    evaluated = result["evaluated"]
    matched = len(result["matches"])
    match_rate = round((100 * matched / evaluated) if evaluated else 0, 2)
    false_positive_estimate = _assess_false_positives(rule, match_rate)
    confidence = round(min(0.95, 0.5 + evaluated / sample_limit), 2)
    if not matched:
        recommendation = (
            "Broaden conditions or extend the lookback window before promoting this rule."
        )
    elif match_rate > 25:
        recommendation = "Tighten conditions to reduce expected alert volume and false positives."
    elif false_positive_estimate > 15:
        recommendation = "Add corroboration conditions before enabling high-confidence response."
    else:
        recommendation = "Rule shows usable signal; keep under analyst review during rollout."

    return {
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "rule_type": rule.rule_type,
        "enabled": rule.enabled,
        "lookback_hours": hours,
        "evaluated": evaluated,
        "matched": matched,
        "match_rate": match_rate,
        "average_matches_per_day": round(matched / max(1, hours / 24), 2),
        "false_positive_estimate": false_positive_estimate,
        "confidence": confidence,
        "severity_distribution": dict(
            Counter(
                item.get("severity", "N/A") for item in result["matches"] if isinstance(item, dict)
            )
        ),
        "source_distribution": dict(
            Counter(
                item.get("source_ip", item.get("value", "N/A"))
                for item in result["matches"]
                if isinstance(item, dict)
            )
        ),
        "sample": result["matches"][:10],
        "recommendation": recommendation,
        "simulation_only": True,
        "generated_at": datetime.now(dt_timezone.utc).isoformat(),
    }


def backtest_all(organization, lookback_hours=168, limit=500):
    rules = DetectionRule.objects.filter(organization=organization).order_by("rule_id")
    results = [backtest_rule(rule, lookback_hours, limit) for rule in rules[:50]]
    return {
        "rules_evaluated": len(results),
        "total_matches": sum(item["matched"] for item in results),
        "average_match_rate": round(sum(item["match_rate"] for item in results) / len(results), 2)
        if results
        else 0,
        "results": results,
        "generated_at": datetime.now(dt_timezone.utc).isoformat(),
    }
