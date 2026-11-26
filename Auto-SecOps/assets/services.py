from datetime import timedelta

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from assets.models import Asset, AssetRiskAssessment, Vulnerability
from audit.services import log_action
from incidents.models import SecurityIncident
from incidents.services import add_investigation_note


def _asset_values(asset):
    values = {asset.hostname, asset.asset_id}
    values.update(str(item) for item in asset.ip_addresses if item)
    values.update(str(item) for item in asset.mac_addresses if item)
    return {value.lower() for value in values if value}


def _contains_value(text, values):
    lowered = str(text or "").lower()
    return any(value in lowered for value in values if value)


def _risk_level(score):
    if score >= 75:
        return AssetRiskAssessment.RiskLevel.CRITICAL
    if score >= 50:
        return AssetRiskAssessment.RiskLevel.HIGH
    if score >= 25:
        return AssetRiskAssessment.RiskLevel.MEDIUM
    return AssetRiskAssessment.RiskLevel.LOW


def _vulnerability_factors(asset):
    factors = []
    vulnerabilities = Vulnerability.objects.filter(
        organization=asset.organization, asset=asset
    ).exclude(status__in=[Vulnerability.Status.REMEDIATED, Vulnerability.Status.RISK_ACCEPTED])
    if not vulnerabilities.exists():
        return factors, []
    scores = [float(item.cvss_score or 0) for item in vulnerabilities]
    max_score = max(scores)
    factors.append(
        {
            "label": "Highest open CVSS",
            "weight": round(min(20.0, max_score * 2), 1),
            "detail": f"Maximum open vulnerability CVSS is {max_score:.1f}.",
        }
    )
    if any(item.exploit_available for item in vulnerabilities):
        factors.append(
            {
                "label": "Known exploit available",
                "weight": 10,
                "detail": "At least one open vulnerability has a known exploit.",
            }
        )
    high_count = sum(
        1
        for item in vulnerabilities
        if item.severity in {Vulnerability.Severity.HIGH, Vulnerability.Severity.CRITICAL}
    )
    if high_count:
        factors.append(
            {
                "label": "Multiple high-severity vulnerabilities",
                "weight": min(15, high_count * 5),
                "detail": f"{high_count} high or critical vulnerability(ies) are open.",
            }
        )
    return factors, list(vulnerabilities.values_list("cve", flat=True))


def _indicator_factors(asset, values):
    from intelligence.models import ThreatIntelligenceRecord

    factors = []
    indicators = []
    records = ThreatIntelligenceRecord.objects.filter(
        organization=asset.organization, malicious=True
    ).select_related("indicator")[:500]
    for record in records:
        value = record.indicator.value.lower()
        if (
            value not in values
            and not _contains_value(value, values)
            and value not in str(asset.hostname).lower()
        ):
            continue
        indicators.append(
            {
                "id": record.indicator_id,
                "type": record.indicator.indicator_type,
                "value": record.indicator.value,
                "confidence": record.confidence,
            }
        )
    if indicators:
        factors.append(
            {
                "label": "Malicious threat intelligence match",
                "weight": 12,
                "detail": f"{len(indicators)} malicious indicator(s) relate to this asset.",
            }
        )
        if any(item["confidence"] >= 80 for item in indicators):
            factors.append(
                {
                    "label": "High-confidence intelligence",
                    "weight": 8,
                    "detail": "At least one matched indicator has confidence 80 or higher.",
                }
            )
    return factors, indicators


def _alert_factors(asset, values):
    from alerts.models import SecurityAlert

    since = timezone.now() - timedelta(days=7)
    factors = []
    alerts = []
    queryset = (
        SecurityAlert.objects.filter(organization=asset.organization, received_at__gte=since)
        .select_related("classification")
        .order_by("-received_at")[:500]
    )
    for alert in queryset:
        related = (
            alert.source_ip.lower() in values
            or alert.destination_ip.lower() in values
            or _contains_value(alert.title, values)
            or _contains_value(alert.description, values)
        )
        if related:
            try:
                risk_score = alert.classification.risk_score
            except ObjectDoesNotExist:
                risk_score = 0
            alerts.append(
                {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "risk_score": risk_score,
                }
            )
    if alerts:
        severity_weight = (
            20 if any(item["severity"] in {"HIGH", "CRITICAL"} for item in alerts) else 8
        )
        factors.append(
            {
                "label": "Recent related alerts",
                "weight": severity_weight,
                "detail": f"{len(alerts)} alert(s) referenced this asset in the last 7 days.",
            }
        )
        max_risk = max(item["risk_score"] for item in alerts)
        if max_risk >= 60:
            factors.append(
                {
                    "label": "High-risk alert classification",
                    "weight": min(15, max_risk // 5),
                    "detail": f"Highest related alert risk score is {max_risk}.",
                }
            )
    return factors, alerts


def _detection_factors(asset, values):
    from detections.models import DetectionHit

    since = timezone.now() - timedelta(days=7)
    factors = []
    hits = []
    queryset = DetectionHit.objects.filter(
        organization=asset.organization, detected_at__gte=since
    ).select_related("rule")[:500]
    for hit in queryset:
        evidence_text = " ".join(
            str(item) for item in (hit.evidence or {}).values() if not isinstance(item, list)
        )
        if _contains_value(evidence_text, values) or _contains_value(hit.title, values):
            hits.append(
                {
                    "id": hit.id,
                    "title": hit.title,
                    "severity": hit.severity,
                    "rule": hit.rule.rule_id,
                }
            )
    if hits:
        factors.append(
            {
                "label": "Related detection hits",
                "weight": min(15, len(hits) * 5),
                "detail": f"{len(hits)} detection hit(s) referenced this asset.",
            }
        )
    return factors, hits


def compute_asset_risk(asset, actor=None, persist=True):
    values = _asset_values(asset)
    factors = []
    criticality_weights = {
        Asset.Criticality.LOW: 5,
        Asset.Criticality.MEDIUM: 12,
        Asset.Criticality.HIGH: 22,
        Asset.Criticality.CRITICAL: 35,
    }
    factors.append(
        {
            "label": "Business criticality",
            "weight": criticality_weights.get(asset.business_criticality, 12),
            "detail": f"Asset criticality is {asset.business_criticality}.",
        }
    )
    if asset.internet_exposed:
        factors.append(
            {
                "label": "Internet exposure",
                "weight": 15,
                "detail": "Asset is marked as internet exposed.",
            }
        )
    if asset.environment == Asset.Environment.PRODUCTION:
        factors.append(
            {
                "label": "Production environment",
                "weight": 8,
                "detail": "Asset runs in production.",
            }
        )
    vulnerability_factors, vulnerabilities = _vulnerability_factors(asset)
    factors.extend(vulnerability_factors)
    indicator_factors, indicators = _indicator_factors(asset, values)
    factors.extend(indicator_factors)
    alert_factors, alerts = _alert_factors(asset, values)
    factors.extend(alert_factors)
    detection_factors, hits = _detection_factors(asset, values)
    factors.extend(detection_factors)

    score = min(100, sum(int(item["weight"]) for item in factors))
    level = _risk_level(score)
    assessment = None
    if persist:
        assessment = AssetRiskAssessment.objects.create(
            organization=asset.organization,
            asset=asset,
            risk_score=score,
            risk_level=level,
            factors=factors,
            contributing_alerts=alerts,
            contributing_hits=hits,
            contributing_indicators=indicators,
            assessed_by=actor,
        )
        log_action(
            asset.organization,
            actor,
            "asset.risk_assessed",
            "Asset",
            asset.id,
            {"score": score, "level": level, "vulnerabilities": vulnerabilities},
        )
    else:
        assessment = AssetRiskAssessment(
            organization=asset.organization,
            asset=asset,
            risk_score=score,
            risk_level=level,
            factors=factors,
            contributing_alerts=alerts,
            contributing_hits=hits,
            contributing_indicators=indicators,
            assessed_by=actor,
        )
    return assessment


def latest_assessment(asset):
    return AssetRiskAssessment.objects.filter(asset=asset).order_by("-assessed_at").first()


def reassess_assets(organization, actor=None):
    results = []
    for asset in Asset.objects.filter(organization=organization, status=Asset.Status.ACTIVE):
        assessment = compute_asset_risk(asset, actor)
        results.append(
            {
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "score": assessment.risk_score,
                "level": assessment.risk_level,
            }
        )
    return results


def create_incident_for_asset(asset, actor=None, assessment=None):
    assessment = assessment or latest_assessment(asset) or compute_asset_risk(asset, actor)
    severity_map = {
        AssetRiskAssessment.RiskLevel.CRITICAL: (
            SecurityIncident.Severity.CRITICAL,
            SecurityIncident.Priority.P1,
        ),
        AssetRiskAssessment.RiskLevel.HIGH: (
            SecurityIncident.Severity.HIGH,
            SecurityIncident.Priority.P2,
        ),
        AssetRiskAssessment.RiskLevel.MEDIUM: (
            SecurityIncident.Severity.MEDIUM,
            SecurityIncident.Priority.P3,
        ),
        AssetRiskAssessment.RiskLevel.LOW: (
            SecurityIncident.Severity.LOW,
            SecurityIncident.Priority.P4,
        ),
    }
    severity, priority = severity_map.get(
        assessment.risk_level,
        (SecurityIncident.Severity.MEDIUM, SecurityIncident.Priority.P3),
    )
    factors = "; ".join(f"{item['label']}: {item['detail']}" for item in (assessment.factors or []))
    incident = SecurityIncident.objects.create(
        organization=asset.organization,
        title=f"Asset risk: {asset.hostname}",
        description=(
            f"Risk assessment {assessment.risk_level} ({assessment.risk_score}/100). {factors}"
        ),
        severity=severity,
        priority=priority,
        risk_score=assessment.risk_score,
        created_by=actor,
        recommendations=[
            "Validate asset ownership and exposure.",
            "Prioritize open vulnerabilities with known exploits.",
            "Do not apply blocking or isolation actions without approval.",
        ],
    )
    add_investigation_note(
        incident,
        actor,
        f"Created from asset risk assessment for {asset.hostname} ({asset.asset_id}).",
    )
    log_action(
        asset.organization,
        actor,
        "asset.incident_created",
        "SecurityIncident",
        incident.id,
        {"asset_id": asset.asset_id, "score": assessment.risk_score},
    )
    return incident
