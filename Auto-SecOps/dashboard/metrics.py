from collections import Counter
from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from alerts.models import AlertClassification, SecurityAlert
from assets.models import Asset, AssetRiskAssessment, Vulnerability
from automation.models import ApprovalRequest, WorkflowExecution
from detections.models import DetectionHit, DetectionRule
from incidents.models import IncidentAssignment, SecurityIncident
from intelligence.models import ThreatIntelligenceRecord


def _duration_minutes(start, end):
    if not start or not end:
        return None
    return max(0.0, (end - start).total_seconds() / 60.0)


def _average(values):
    values = [value for value in values if value is not None]
    return round(sum(values) / len(values), 1) if values else 0.0


def _with_bars(items, value_key="value"):
    maximum = max([int(item.get(value_key, 0) or 0) for item in items], default=0) or 1
    results = []
    for item in items:
        enriched = dict(item)
        enriched["percent"] = round(100 * int(item.get(value_key, 0) or 0) / maximum)
        results.append(enriched)
    return results


def get_metrics(organization):
    alerts = SecurityAlert.objects.filter(organization=organization)
    incidents = SecurityIncident.objects.filter(organization=organization)
    classifications = AlertClassification.objects.filter(alert__organization=organization)
    alert_count = alerts.count()
    incident_count = incidents.count()
    open_incidents = incidents.exclude(
        status__in=[SecurityIncident.Status.RESOLVED, SecurityIncident.Status.CLOSED]
    ).count()
    critical_incidents = (
        incidents.filter(severity=SecurityIncident.Severity.CRITICAL)
        .exclude(status=SecurityIncident.Status.CLOSED)
        .count()
    )
    pending_approvals = ApprovalRequest.objects.filter(
        organization=organization, status=ApprovalRequest.Status.PENDING
    ).count()
    sla_threshold = timezone.now() - timedelta(hours=24)
    sla_breaches = (
        incidents.filter(created_at__lt=sla_threshold)
        .exclude(status__in=[SecurityIncident.Status.RESOLVED, SecurityIncident.Status.CLOSED])
        .count()
    )

    ack_times = [
        _duration_minutes(incident.created_at, incident.acknowledged_at)
        for incident in incidents.iterator()
    ]
    resolution_times = [
        _duration_minutes(incident.created_at, incident.resolved_at)
        for incident in incidents.iterator()
    ]

    category_counts = Counter(classifications.values_list("category", flat=True))
    severity_counts = Counter(alerts.values_list("severity", flat=True))
    status_counts = Counter(incidents.values_list("status", flat=True))
    workflow_counts = Counter(
        WorkflowExecution.objects.filter(organization=organization).values_list("status", flat=True)
    )

    daily_alerts = list(
        alerts.annotate(day=TruncDate("received_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")[:30]
    )
    for item in daily_alerts:
        item["day"] = item["day"].isoformat() if item["day"] else ""

    recent_alerts = [
        {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "received_at": alert.received_at.isoformat(),
        }
        for alert in alerts.select_related("source").order_by("-received_at")[:8]
    ]
    workload = list(
        IncidentAssignment.objects.filter(
            incident__organization=organization,
            active=True,
        )
        .values("user__username", "user__display_name")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    for item in workload:
        item["label"] = item["user__display_name"] or item["user__username"]

    malicious_count = ThreatIntelligenceRecord.objects.filter(
        organization=organization, malicious=True
    ).count()
    detection_hits = DetectionHit.objects.filter(organization=organization)
    new_detection_hits = detection_hits.filter(status=DetectionHit.Status.NEW).count()
    enabled_detection_rules = DetectionRule.objects.filter(
        organization=organization, enabled=True
    ).count()
    detection_status_counts = Counter(detection_hits.values_list("status", flat=True))
    detection_rule_counts = list(
        detection_hits.values("rule__name").annotate(count=Count("id")).order_by("-count")[:10]
    )
    for item in detection_rule_counts:
        item["label"] = item.pop("rule__name")
    recent_detection_hits = [
        {
            "id": hit.id,
            "title": hit.title,
            "severity": hit.severity,
            "status": hit.status,
            "detected_at": hit.detected_at.isoformat(),
            "rule": hit.rule.rule_id,
        }
        for hit in detection_hits.select_related("rule").order_by("-detected_at")[:8]
    ]
    assets = Asset.objects.filter(organization=organization)
    asset_count = assets.count()
    latest_risks = {}
    for assessment in (
        AssetRiskAssessment.objects.filter(organization=organization)
        .select_related("asset")
        .order_by("assessed_at")
    ):
        latest_risks[assessment.asset_id] = assessment
    asset_risk_counts = Counter(assessment.risk_level for assessment in latest_risks.values())
    critical_risk_assets = sum(
        1
        for assessment in latest_risks.values()
        if assessment.risk_level == AssetRiskAssessment.RiskLevel.CRITICAL
    )
    open_vulnerabilities = Vulnerability.objects.filter(
        organization=organization,
        status__in=[Vulnerability.Status.OPEN, Vulnerability.Status.IN_PROGRESS],
    )
    exploitable_vulnerabilities = open_vulnerabilities.filter(exploit_available=True).count()
    asset_type_counts = Counter(assets.values_list("asset_type", flat=True))
    recent_asset_risks = [
        {
            "asset": assessment.asset.hostname,
            "score": assessment.risk_score,
            "level": assessment.risk_level,
            "assessed_at": assessment.assessed_at.isoformat(),
        }
        for assessment in AssetRiskAssessment.objects.filter(organization=organization)
        .select_related("asset")
        .order_by("-assessed_at")[:8]
    ]

    return {
        "generated_at": timezone.now().isoformat(),
        "organization": organization.name,
        "cards": {
            "total_alerts": alert_count,
            "total_incidents": incident_count,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "pending_approvals": pending_approvals,
            "sla_breaches": sla_breaches,
            "malicious_indicators": malicious_count,
            "new_detection_hits": new_detection_hits,
            "enabled_detection_rules": enabled_detection_rules,
            "total_assets": asset_count,
            "critical_risk_assets": critical_risk_assets,
            "open_vulnerabilities": open_vulnerabilities.count(),
            "exploitable_vulnerabilities": exploitable_vulnerabilities,
            "mean_time_to_acknowledge_minutes": _average(ack_times),
            "mean_time_to_resolve_minutes": _average(resolution_times),
        },
        "charts": {
            "categories": _with_bars(
                [{"label": key, "value": value} for key, value in category_counts.items()]
            ),
            "severities": _with_bars(
                [{"label": key, "value": value} for key, value in severity_counts.items()]
            ),
            "incident_statuses": _with_bars(
                [{"label": key, "value": value} for key, value in status_counts.items()]
            ),
            "workflow_statuses": _with_bars(
                [{"label": key, "value": value} for key, value in workflow_counts.items()]
            ),
            "daily_alerts": daily_alerts,
            "analyst_workload": _with_bars(workload, "count"),
            "detection_statuses": _with_bars(
                [{"label": key, "value": value} for key, value in detection_status_counts.items()]
            ),
            "detection_rules": _with_bars(detection_rule_counts, "count"),
            "asset_risk_levels": _with_bars(
                [{"label": key, "value": value} for key, value in asset_risk_counts.items()]
            ),
            "asset_types": _with_bars(
                [{"label": key, "value": value} for key, value in asset_type_counts.items()]
            ),
        },
        "recent_alerts": recent_alerts,
        "recent_detection_hits": recent_detection_hits,
        "recent_asset_risks": recent_asset_risks,
    }
