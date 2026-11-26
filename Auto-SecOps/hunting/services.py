import json
import shlex
from datetime import datetime
from datetime import timezone as dt_timezone

from django.utils import timezone

from audit.services import log_action
from hunting.models import SavedHunt

FILTER_KEYS = {
    "type",
    "severity",
    "status",
    "risk",
    "ip",
    "host",
    "user",
    "cve",
    "tag",
    "confidence",
}

TYPE_LABELS = {
    "alert": "Alerts",
    "incident": "Incidents",
    "detection": "Detections",
    "asset": "Assets",
    "vulnerability": "Vulnerabilities",
    "indicator": "Indicators",
}


def parse_query(raw_query):
    raw = (raw_query or "").strip()
    if not raw:
        return {}, []
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    filters = {}
    terms = []
    for token in tokens:
        if ":" in token:
            key, value = token.split(":", 1)
            key = key.strip().lower()
            value = value.strip().lower()
            if key in FILTER_KEYS and value:
                filters.setdefault(key, []).append(value)
                continue
        terms.append(token)
    return filters, terms


def _values(filters, key):
    return [str(value).lower() for value in filters.get(key, [])]


def _min_number(filters, key):
    values = _values(filters, key)
    if not values:
        return 0
    try:
        return max(0, int(float(values[-1])))
    except ValueError:
        return 0


def _matches_text(terms, values):
    if not terms:
        return True
    blob = " ".join(str(value or "") for value in values).lower()
    return all(str(term).lower() in blob for term in terms)


def _matches_values(candidates, needles):
    if not needles:
        return True
    normalized = [str(candidate or "").lower() for candidate in candidates]
    return any(
        needle in candidate or candidate in needle
        for needle in needles
        for candidate in normalized
        if candidate
    )


def _matches_filters(filters, values):
    severities = _values(filters, "severity")
    if severities and str(values.get("severity", "")).lower() not in severities:
        return False
    statuses = _values(filters, "status")
    if statuses and str(values.get("status", "")).lower() not in statuses:
        return False
    if _min_number(filters, "risk") > int(values.get("risk") or 0):
        return False
    if _min_number(filters, "confidence") > int(values.get("confidence") or 0):
        return False
    if not _matches_values(values.get("ips", []), _values(filters, "ip")):
        return False
    if not _matches_values(values.get("hosts", []), _values(filters, "host")):
        return False
    if not _matches_values(values.get("users", []), _values(filters, "user")):
        return False
    if not _matches_values(values.get("cves", []), _values(filters, "cve")):
        return False
    if not _matches_values(values.get("tags", []), _values(filters, "tag")):
        return False
    return True


def _selected_types(filters):
    values = _values(filters, "type")
    if not values:
        return None
    selected = set()
    for value in values:
        if value.startswith("alert"):
            selected.add("alert")
        elif value.startswith("incident") or value.startswith("case"):
            selected.add("incident")
        elif value.startswith("detect") or value.startswith("hit"):
            selected.add("detection")
        elif value.startswith("vuln") or value == "cve":
            selected.add("vulnerability")
        elif value.startswith("indicator") or value.startswith("ioc") or value.startswith("intel"):
            selected.add("indicator")
        elif value.startswith("asset") or value.startswith("host"):
            selected.add("asset")
    return selected or None


def _item(obj, title, subtitle, url, badge):
    return {
        "id": getattr(obj, "id", None),
        "title": title,
        "subtitle": subtitle,
        "url": url,
        "badge": str(badge or ""),
    }


def _add_group(groups, label, items):
    if items:
        groups.append({"label": label, "items": items})


def execute_hunt(organization, raw_query, limit=100):
    filters, terms = parse_query(raw_query)
    selected_types = _selected_types(filters)
    per_group = max(1, min(50, int(limit or 100)))
    groups = []
    summary = {"total": 0, "by_type": {}, "parsed_filters": filters, "terms": terms}

    def include(kind):
        return selected_types is None or kind in selected_types

    if include("alert"):
        from alerts.models import SecurityAlert

        alerts = []
        for alert in SecurityAlert.objects.filter(organization=organization)[:1500]:
            classification = getattr(alert, "classification", None)
            risk = classification.risk_score if classification else 0
            if not _matches_filters(
                filters,
                {
                    "severity": alert.severity,
                    "status": alert.status,
                    "risk": risk,
                    "ips": [alert.source_ip, alert.destination_ip],
                    "hosts": [alert.title],
                    "users": [alert.user_identity],
                    "tags": [alert.alert_type],
                },
            ):
                continue
            if not _matches_text(
                terms,
                [
                    alert.title,
                    alert.description,
                    alert.external_id,
                    alert.source_ip,
                    alert.destination_ip,
                    alert.user_identity,
                    alert.alert_type,
                ],
            ):
                continue
            alerts.append(
                _item(
                    alert,
                    alert.title,
                    f"{alert.severity} | {alert.status} | {alert.source_ip or 'no source IP'}",
                    "/alerts/",
                    alert.severity,
                )
            )
            if len(alerts) >= per_group:
                break
        _add_group(groups, TYPE_LABELS["alert"], alerts)
        summary["by_type"]["alerts"] = len(alerts)

    if include("incident"):
        from incidents.models import SecurityIncident

        incidents = []
        for incident in SecurityIncident.objects.filter(organization=organization)[:1500]:
            if not _matches_filters(
                filters,
                {
                    "severity": incident.severity,
                    "status": incident.status,
                    "risk": incident.risk_score,
                },
            ):
                continue
            if not _matches_text(terms, [incident.title, incident.description, incident.priority]):
                continue
            incidents.append(
                _item(
                    incident,
                    incident.title,
                    f"{incident.severity} | {incident.priority} | {incident.status}",
                    "/incidents/",
                    incident.status,
                )
            )
            if len(incidents) >= per_group:
                break
        _add_group(groups, TYPE_LABELS["incident"], incidents)
        summary["by_type"]["incidents"] = len(incidents)

    if include("detection"):
        from detections.models import DetectionHit

        hits = []
        for hit in DetectionHit.objects.filter(organization=organization).select_related("rule")[
            :1500
        ]:
            evidence_text = json.dumps(hit.evidence or {}, default=str)
            if not _matches_filters(filters, {"severity": hit.severity, "status": hit.status}):
                continue
            if not _matches_text(terms, [hit.title, hit.summary, hit.fingerprint, evidence_text]):
                continue
            hits.append(
                _item(
                    hit,
                    hit.title,
                    f"{hit.severity} | {hit.status} | {hit.rule.rule_id}",
                    "/detections/",
                    hit.status,
                )
            )
            if len(hits) >= per_group:
                break
        _add_group(groups, TYPE_LABELS["detection"], hits)
        summary["by_type"]["detections"] = len(hits)

    if include("asset"):
        from assets.models import Asset

        assets = []
        for asset in Asset.objects.filter(organization=organization)[:1500]:
            if not _matches_filters(
                filters,
                {
                    "severity": asset.business_criticality,
                    "status": asset.status,
                    "hosts": [asset.hostname, asset.asset_id],
                    "ips": asset.ip_addresses or [],
                    "tags": asset.tags or [],
                },
            ):
                continue
            if not _matches_text(
                terms,
                [asset.hostname, asset.asset_id, asset.owner, asset.department, asset.description],
            ):
                continue
            assets.append(
                _item(
                    asset,
                    asset.hostname,
                    f"{asset.asset_id} | {asset.business_criticality} | {asset.environment}",
                    "/assets/",
                    asset.business_criticality,
                )
            )
            if len(assets) >= per_group:
                break
        _add_group(groups, TYPE_LABELS["asset"], assets)
        summary["by_type"]["assets"] = len(assets)

    if include("vulnerability"):
        from assets.models import Vulnerability

        vulnerabilities = []
        for vulnerability in Vulnerability.objects.filter(organization=organization)[:1500]:
            if not _matches_filters(
                filters,
                {
                    "severity": vulnerability.severity,
                    "status": vulnerability.status,
                    "cves": [vulnerability.cve],
                    "risk": int(vulnerability.cvss_score or 0) * 10,
                },
            ):
                continue
            if not _matches_text(
                terms,
                [vulnerability.cve, vulnerability.title, vulnerability.description],
            ):
                continue
            vulnerabilities.append(
                _item(
                    vulnerability,
                    f"{vulnerability.cve} - {vulnerability.title}",
                    f"{vulnerability.severity} | CVSS {vulnerability.cvss_score} | {vulnerability.status}",
                    "/assets/",
                    vulnerability.severity,
                )
            )
            if len(vulnerabilities) >= per_group:
                break
        _add_group(groups, TYPE_LABELS["vulnerability"], vulnerabilities)
        summary["by_type"]["vulnerabilities"] = len(vulnerabilities)

    if include("indicator"):
        from intelligence.models import ThreatIndicator

        indicators = ThreatIndicator.objects.filter(organization=organization)
        confidence = _min_number(filters, "confidence")
        if confidence:
            indicators = indicators.filter(
                intelligence_records__malicious=True,
                intelligence_records__confidence__gte=confidence,
            ).distinct()
        values = []
        for indicator in indicators[:1500]:
            if not _matches_filters(
                filters,
                {
                    "status": indicator.indicator_type,
                    "ips": [indicator.value],
                    "hosts": [indicator.value],
                    "tags": indicator.tags or [],
                },
            ):
                continue
            if not _matches_text(terms, [indicator.value, indicator.indicator_type]):
                continue
            values.append(
                _item(
                    indicator,
                    indicator.value,
                    f"{indicator.indicator_type} | {', '.join(indicator.tags or []) or 'no tags'}",
                    "/intelligence/",
                    indicator.indicator_type,
                )
            )
            if len(values) >= per_group:
                break
        _add_group(groups, TYPE_LABELS["indicator"], values)
        summary["by_type"]["indicators"] = len(values)

    summary["total"] = sum(summary["by_type"].values())
    summary["generated_at"] = datetime.now(dt_timezone.utc).isoformat()
    return {
        "query": raw_query or "",
        "filters": filters,
        "terms": terms,
        "summary": summary,
        "groups": groups,
    }


def save_hunt(organization, actor, name, query, description=""):
    clean_name = (name or "").strip()
    clean_query = (query or "").strip()
    if not clean_name:
        raise ValueError("Hunt name is required.")
    if not clean_query:
        raise ValueError("Hunt query is required.")
    hunt, created = SavedHunt.objects.get_or_create(
        organization=organization,
        name=clean_name,
        defaults={"query": clean_query, "description": description or ""},
    )
    if created:
        hunt.created_by = actor
        hunt.save(update_fields=["created_by"])
    else:
        hunt.query = clean_query
        hunt.description = description or hunt.description
        hunt.save(update_fields=["query", "description", "updated_at"])
    log_action(
        organization,
        actor,
        "hunt.saved" if created else "hunt.updated",
        "SavedHunt",
        hunt.id,
        {"name": hunt.name, "query": hunt.query},
    )
    return hunt, created


def mark_hunt_run(hunt, result_count, actor=None):
    hunt.last_run_at = timezone.now()
    hunt.last_result_count = int(result_count or 0)
    hunt.save(update_fields=["last_run_at", "last_result_count", "updated_at"])
    log_action(
        hunt.organization,
        actor,
        "hunt.executed",
        "SavedHunt",
        hunt.id,
        {"name": hunt.name, "results": hunt.last_result_count},
    )
    return hunt
