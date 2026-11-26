from urllib.parse import urlencode

from django.db.models import Q


def _url(path, query=""):
    if not query:
        return path
    return f"{path}?{urlencode({'q': query})}"


def _items(queryset, title_field, subtitle_fields, url_path, query, badge_field=None):
    results = []
    for item in queryset:
        subtitle_parts = []
        for field in subtitle_fields:
            value = getattr(item, field, "")
            if value:
                subtitle_parts.append(str(value))
        results.append(
            {
                "title": str(getattr(item, title_field, "")),
                "subtitle": " | ".join(subtitle_parts)[:240],
                "url": _url(url_path, query),
                "badge": str(getattr(item, badge_field, "")) if badge_field else "",
                "id": getattr(item, "id", None),
            }
        )
    return results


def global_search(organization, raw_query, limit=8):
    query = (raw_query or "").strip()
    if not query:
        return {"query": "", "count": 0, "groups": []}
    per_group = max(1, min(20, int(limit or 8)))
    groups = []

    from alerts.models import SecurityAlert

    alerts = SecurityAlert.objects.filter(organization=organization).filter(
        Q(title__icontains=query)
        | Q(external_id__icontains=query)
        | Q(source_ip__icontains=query)
        | Q(destination_ip__icontains=query)
        | Q(user_identity__icontains=query)
        | Q(description__icontains=query)
    )[:per_group]
    alert_items = _items(
        alerts,
        "title",
        ["external_id", "source_ip", "user_identity"],
        "/alerts/",
        query,
        "severity",
    )
    if alert_items:
        groups.append({"label": "Alerts", "items": alert_items})

    from incidents.models import SecurityIncident

    incidents = SecurityIncident.objects.filter(organization=organization).filter(
        Q(title__icontains=query) | Q(description__icontains=query)
    )[:per_group]
    incident_items = _items(
        incidents,
        "title",
        ["status", "severity", "priority"],
        "/incidents/",
        query,
        "status",
    )
    if incident_items:
        groups.append({"label": "Incidents", "items": incident_items})

    from detections.models import DetectionHit

    hits = (
        DetectionHit.objects.filter(organization=organization)
        .filter(
            Q(title__icontains=query)
            | Q(summary__icontains=query)
            | Q(fingerprint__icontains=query)
        )
        .select_related("rule")[:per_group]
    )
    hit_items = []
    for hit in hits:
        hit_items.append(
            {
                "title": hit.title,
                "subtitle": f"{hit.rule.rule_id} | {hit.status}",
                "url": "/detections/",
                "badge": hit.severity,
                "id": hit.id,
            }
        )
    if hit_items:
        groups.append({"label": "Detections", "items": hit_items})

    from assets.models import Asset, Vulnerability

    assets = Asset.objects.filter(organization=organization).filter(
        Q(hostname__icontains=query)
        | Q(asset_id__icontains=query)
        | Q(owner__icontains=query)
        | Q(department__icontains=query)
        | Q(description__icontains=query)
    )[:per_group]
    asset_items = _items(
        assets,
        "hostname",
        ["asset_id", "owner", "business_criticality"],
        "/assets/",
        query,
        "business_criticality",
    )
    if asset_items:
        groups.append({"label": "Assets", "items": asset_items})

    vulnerabilities = (
        Vulnerability.objects.filter(organization=organization)
        .filter(Q(cve__icontains=query) | Q(title__icontains=query))
        .select_related("asset")[:per_group]
    )
    vulnerability_items = []
    for vulnerability in vulnerabilities:
        vulnerability_items.append(
            {
                "title": f"{vulnerability.cve} - {vulnerability.title}",
                "subtitle": f"{vulnerability.asset.hostname} | {vulnerability.status}",
                "url": "/assets/",
                "badge": vulnerability.severity,
                "id": vulnerability.id,
            }
        )
    if vulnerability_items:
        groups.append({"label": "Vulnerabilities", "items": vulnerability_items})

    from intelligence.models import ThreatIndicator

    indicators = ThreatIndicator.objects.filter(organization=organization).filter(
        Q(value__icontains=query) | Q(indicator_type__icontains=query)
    )[:per_group]
    indicator_items = _items(
        indicators,
        "value",
        ["indicator_type"],
        "/intelligence/",
        query,
        "indicator_type",
    )
    if indicator_items:
        groups.append({"label": "Indicators", "items": indicator_items})

    from audit.models import AuditLog

    audit_logs = AuditLog.objects.filter(organization=organization).filter(
        Q(action__icontains=query) | Q(target_type__icontains=query) | Q(target_id__icontains=query)
    )[:per_group]
    audit_items = _items(
        audit_logs,
        "action",
        ["target_type", "target_id"],
        "/audit/",
        "",
        "target_type",
    )
    if audit_items:
        groups.append({"label": "Audit", "items": audit_items})

    from reports.models import Report

    reports = Report.objects.filter(organization=organization).filter(
        Q(title__icontains=query) | Q(report_type__icontains=query)
    )[:per_group]
    report_items = _items(
        reports,
        "title",
        ["report_type"],
        "/reports/",
        "",
        "report_type",
    )
    if report_items:
        groups.append({"label": "Reports", "items": report_items})

    from hunting.models import SavedHunt

    hunts = SavedHunt.objects.filter(organization=organization).filter(
        Q(name__icontains=query) | Q(query__icontains=query) | Q(description__icontains=query)
    )[:per_group]
    hunt_items = _items(hunts, "name", ["query"], "/hunting/", query)
    if hunt_items:
        groups.append({"label": "Saved Hunts", "items": hunt_items})

    return {
        "query": query,
        "count": sum(len(group["items"]) for group in groups),
        "groups": groups,
    }
