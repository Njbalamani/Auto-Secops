import json
from collections import Counter
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.utils import timezone

from assets.models import Asset, Vulnerability
from detections.models import DetectionHit
from incidents.models import SecurityIncident
from intelligence.models import ThreatIndicator

CRITICALITY_WEIGHT = {
    Asset.Criticality.LOW: 5,
    Asset.Criticality.MEDIUM: 10,
    Asset.Criticality.HIGH: 15,
    Asset.Criticality.CRITICAL: 20,
}


def _clamp(value, low=0, high=100):
    return max(low, min(high, int(value)))


def _severity(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _asset_values(asset):
    values = {str(asset.hostname or "").lower(), str(asset.asset_id or "").lower()}
    values.update(str(value or "").lower() for value in asset.ip_addresses or [])
    return {value for value in values if value}


def _contains_any(text, values):
    lower = str(text or "").lower()
    return any(value in lower for value in values)


def _collect_evidence(organization, asset, values):
    from alerts.models import SecurityAlert

    alert_ids = []
    source_ips = []
    destination_ips = []
    for alert in SecurityAlert.objects.filter(organization=organization)[:1000]:
        haystack = " ".join(
            [
                alert.title,
                alert.description,
                alert.source_ip,
                alert.destination_ip,
                alert.user_identity,
                alert.external_id,
            ]
        )
        if not _contains_any(haystack, values):
            continue
        alert_ids.append(alert.id)
        if alert.source_ip:
            source_ips.append(alert.source_ip)
        if alert.destination_ip:
            destination_ips.append(alert.destination_ip)

    hit_ids = []
    hit_evidence = []
    for hit in DetectionHit.objects.filter(organization=organization).select_related("rule")[:1000]:
        evidence_text = json.dumps(hit.evidence or {}, default=str)
        if hit.alert_id not in alert_ids and not _contains_any(evidence_text, values):
            continue
        hit_ids.append(hit.id)
        hit_evidence.append(
            {"title": hit.title, "rule": hit.rule.rule_id, "evidence": hit.evidence}
        )

    incident_ids = []
    for incident in SecurityIncident.objects.filter(organization=organization)[:1000]:
        text = " ".join([incident.title, incident.description])
        if incident.alert_id not in alert_ids and not _contains_any(text, values):
            continue
        incident_ids.append(incident.id)

    indicator_values = []
    for indicator in ThreatIndicator.objects.filter(organization=organization)[:1000]:
        if str(indicator.value or "").lower() in values:
            indicator_values.append(indicator.value)

    return {
        "alert_ids": alert_ids,
        "hit_ids": hit_ids,
        "incident_ids": incident_ids,
        "source_ips": sorted(set(source_ips)),
        "destination_ips": sorted(set(destination_ips)),
        "hit_evidence": hit_evidence[:5],
        "indicator_values": indicator_values,
    }


def _score_path(asset, vulnerability, evidence):
    score = float(vulnerability.cvss_score or 0) * 6
    score += CRITICALITY_WEIGHT.get(asset.business_criticality, 10)
    if asset.internet_exposed:
        score += 10
    if asset.environment == Asset.Environment.PRODUCTION:
        score += 5
    if vulnerability.exploit_available:
        score += 12
    if not vulnerability.patch_available:
        score += 5
    if vulnerability.status in {Vulnerability.Status.OPEN, Vulnerability.Status.IN_PROGRESS}:
        score += 5
    score += min(15, 3 * len(evidence["alert_ids"]))
    score += min(12, 4 * len(evidence["hit_ids"]))
    score += min(15, 5 * len(evidence["incident_ids"]))
    score += min(8, 2 * len(evidence["indicator_values"]))
    score = _clamp(score)
    likelihood = "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW"
    impact = (
        "CRITICAL"
        if asset.business_criticality == Asset.Criticality.CRITICAL
        else "HIGH"
        if asset.business_criticality == Asset.Criticality.HIGH
        else "MEDIUM"
    )
    steps = [
        {
            "stage": "Exposure",
            "detail": (
                f"{asset.hostname} is internet exposed via {evidence['source_ips'][0]}"
                if asset.internet_exposed and evidence["source_ips"]
                else f"{asset.hostname} is reachable through internal trust paths"
            ),
        },
        {
            "stage": "Exploitation",
            "detail": f"{vulnerability.cve} ({vulnerability.severity}, CVSS {vulnerability.cvss_score})",
        },
        {
            "stage": "Impact",
            "detail": (
                f"{len(evidence['incident_ids'])} incident(s) and {len(evidence['hit_ids'])} detection hit(s) corroborate impact"
            ),
        },
    ]
    recommendations = []
    if vulnerability.exploit_available:
        recommendations.append(
            "Prioritize emergency patching because a public exploit is available."
        )
    if asset.internet_exposed:
        recommendations.append("Reduce internet exposure with compensating network controls.")
    if evidence["hit_ids"]:
        recommendations.append("Review correlated detection hits before closing the path.")
    if not recommendations:
        recommendations.append("Schedule remediation within the standard patch window.")
    return {
        "id": f"path-{asset.id}-{vulnerability.id}",
        "asset": {
            "id": asset.id,
            "hostname": asset.hostname,
            "asset_id": asset.asset_id,
            "criticality": asset.business_criticality,
            "environment": asset.environment,
            "internet_exposed": asset.internet_exposed,
        },
        "vulnerability": {
            "id": vulnerability.id,
            "cve": vulnerability.cve,
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "cvss_score": str(vulnerability.cvss_score),
            "exploit_available": vulnerability.exploit_available,
            "patch_available": vulnerability.patch_available,
            "status": vulnerability.status,
        },
        "score": score,
        "severity": _severity(score),
        "likelihood": likelihood,
        "impact": impact,
        "entry_point": evidence["source_ips"][0] if evidence["source_ips"] else "external/unknown",
        "lateral_targets": [
            ip for ip in evidence["destination_ips"] if ip.lower() not in _asset_values(asset)
        ],
        "steps": steps,
        "evidence": {
            "alert_ids": evidence["alert_ids"],
            "hit_ids": evidence["hit_ids"],
            "incident_ids": evidence["incident_ids"],
            "indicator_values": evidence["indicator_values"],
            "hit_evidence": evidence["hit_evidence"],
        },
        "recommendation": " ".join(recommendations),
    }


def build_attack_paths(organization, limit=10):
    paths = []
    assets = Asset.objects.filter(organization=organization, status=Asset.Status.ACTIVE)
    for asset in assets.prefetch_related("vulnerabilities"):
        open_vulnerabilities = [
            vulnerability
            for vulnerability in asset.vulnerabilities.all()
            if vulnerability.status in {Vulnerability.Status.OPEN, Vulnerability.Status.IN_PROGRESS}
        ]
        if not open_vulnerabilities:
            continue
        values = _asset_values(asset)
        evidence = _collect_evidence(organization, asset, values)
        for vulnerability in open_vulnerabilities:
            paths.append(_score_path(asset, vulnerability, evidence))
    paths.sort(key=lambda item: item["score"], reverse=True)
    return paths[: max(1, min(50, int(limit or 10)))]


def attack_surface_summary(organization):
    paths = build_attack_paths(organization, limit=50)
    vulnerabilities = Vulnerability.objects.filter(organization=organization)
    assets = Asset.objects.filter(organization=organization)
    return {
        "generated_at": datetime.now(dt_timezone.utc).isoformat(),
        "assets": assets.count(),
        "active_assets": assets.filter(status=Asset.Status.ACTIVE).count(),
        "internet_exposed_assets": assets.filter(internet_exposed=True).count(),
        "critical_assets": assets.filter(business_criticality=Asset.Criticality.CRITICAL).count(),
        "open_vulnerabilities": vulnerabilities.filter(
            status__in=[Vulnerability.Status.OPEN, Vulnerability.Status.IN_PROGRESS]
        ).count(),
        "exploitable_vulnerabilities": vulnerabilities.filter(exploit_available=True).count(),
        "attack_paths": len(paths),
        "critical_paths": sum(1 for path in paths if path["severity"] == "CRITICAL"),
        "severity_distribution": dict(Counter(path["severity"] for path in paths)),
        "top_path": paths[0] if paths else None,
    }


def forecast_risk(organization, days=7):
    window = max(1, min(30, int(days or 7)))
    now = timezone.now()
    recent_since = now - timedelta(days=window)
    prior_since = now - timedelta(days=window * 2)
    paths = build_attack_paths(organization, limit=5)
    current = round(sum(path["score"] for path in paths) / len(paths)) if paths else 0
    from alerts.models import SecurityAlert

    recent_alerts = SecurityAlert.objects.filter(
        organization=organization, received_at__gte=recent_since
    )
    prior_alerts = SecurityAlert.objects.filter(
        organization=organization, received_at__gte=prior_since, received_at__lt=recent_since
    )
    recent_count = recent_alerts.count()
    prior_count = prior_alerts.count()
    recent_high = recent_alerts.filter(severity__in=["HIGH", "CRITICAL"]).count()
    delta = recent_count - prior_count
    adjustment = min(15, delta * 2) if delta > 0 else -min(10, abs(delta))
    adjustment += min(10, recent_high * 2)
    projected = _clamp(current + adjustment)
    if adjustment >= 5:
        trend = "RISING"
    elif adjustment <= -5:
        trend = "FALLING"
    else:
        trend = "STABLE"
    drivers = [
        f"{recent_count} alert(s) in the last {window} day(s) versus {prior_count} in the prior window",
        f"{recent_high} high/critical alert(s) in the current window",
        f"{len(paths)} scored attack path(s) in the live risk fabric",
    ]
    confidence = round(min(0.95, 0.55 + (recent_count + len(paths)) / 40), 2)
    return {
        "generated_at": datetime.now(dt_timezone.utc).isoformat(),
        "window_days": window,
        "current_score": current,
        "projected_score": projected,
        "trend": trend,
        "confidence": confidence,
        "drivers": drivers,
        "method": "deterministic linear trend with live attack-path weighting",
    }
