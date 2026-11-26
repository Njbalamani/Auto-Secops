import ipaddress
import json
import re

import requests
from django.conf import settings
from django.utils import timezone

from alerts.models import SecurityAlert
from audit.services import log_action
from intelligence.mitre import tactics_for_category, techniques_for_category
from intelligence.models import ThreatIndicator, ThreatIntelligenceRecord
from mlengine.services import classify_and_store

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|info|biz|ru|cn|co|xyz|top|link)\b", re.I
)
HASH_PATTERN = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)


def _is_usable_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )


def _add(indicators, indicator_type, value):
    value = str(value).strip()
    if not value:
        return
    if indicator_type == "IP" and not _is_usable_ip(value):
        return
    key = (indicator_type, value.lower())
    if key not in {(item[0], item[1].lower()) for item in indicators}:
        indicators.append((indicator_type, value))


def extract_indicators(alert):
    indicators = []
    normalized = alert.normalized or {}
    for field in ("source_ip", "destination_ip"):
        if normalized.get(field):
            _add(indicators, "IP", normalized[field])
    for key, value in (alert.raw_payload or {}).items():
        if any(term in key.lower() for term in ("domain", "host", "url", "hash", "ip")):
            if isinstance(value, str):
                for match in IP_PATTERN.findall(value):
                    _add(indicators, "IP", match)
                for match in DOMAIN_PATTERN.findall(value):
                    _add(indicators, "DOMAIN", match)
                for match in HASH_PATTERN.findall(value):
                    _add(indicators, "HASH", match)
    text = json.dumps(alert.raw_payload or {}, sort_keys=True)
    for match in IP_PATTERN.findall(text):
        _add(indicators, "IP", match)
    for match in DOMAIN_PATTERN.findall(text):
        _add(indicators, "DOMAIN", match)
    for match in HASH_PATTERN.findall(text):
        _add(indicators, "HASH", match)
    return indicators[:30]


def enrich_alert(alert, actor=None):
    classification = getattr(alert, "classification", None)
    if not classification:
        classification = classify_and_store(alert, actor)
    findings = []
    mitre_techniques = list(techniques_for_category(classification.category))
    for indicator_type, value in extract_indicators(alert):
        indicator, _ = ThreatIndicator.objects.get_or_create(
            organization=alert.organization,
            indicator_type=indicator_type,
            value=value,
            defaults={"tags": [classification.category.lower()]},
        )
        records = ThreatIntelligenceRecord.objects.filter(
            organization=alert.organization,
            indicator=indicator,
        ).order_by("-malicious", "-confidence", "-observed_at")[:5]
        record_summaries = [
            {
                "source_name": record.source_name,
                "source_type": record.source_type,
                "confidence": record.confidence,
                "malicious": record.malicious,
                "observed_at": record.observed_at.isoformat(),
                "tags": record.taxonomy.get("tags", []),
            }
            for record in records
        ]
        malicious = any(record.malicious for record in records)
        for record in records:
            for technique in record.mitre_techniques or []:
                if technique not in mitre_techniques:
                    mitre_techniques.append(technique)
        findings.append(
            {
                "indicator_type": indicator_type,
                "value": value,
                "malicious": malicious,
                "records": record_summaries,
            }
        )
    evidence = dict(classification.evidence or {})
    evidence["enrichment"] = findings
    evidence["mitre_techniques"] = mitre_techniques
    evidence["mitre_tactic"] = tactics_for_category(classification.category)
    classification.evidence = evidence
    classification.save(update_fields=["evidence"])
    normalized = dict(alert.normalized or {})
    normalized["enrichment"] = findings
    normalized["mitre_techniques"] = mitre_techniques
    alert.normalized = normalized
    alert.status = SecurityAlert.Status.ENRICHED
    alert.save(update_fields=["normalized", "status"])
    log_action(
        alert.organization,
        actor,
        "alert.enriched",
        "SecurityAlert",
        alert.id,
        {
            "indicators": len(findings),
            "malicious": sum(1 for item in findings if item["malicious"]),
            "mitre_techniques": len(mitre_techniques),
        },
    )
    return classification, findings


def parse_stix_bundle(bundle):
    if not isinstance(bundle, dict):
        raise ValueError("STIX bundle must be a JSON object.")
    objects = bundle.get("objects", [])
    parsed = []
    for item in objects:
        if item.get("type") != "indicator" or not item.get("pattern"):
            continue
        match = re.search(r"=\s*'([^']+)'", str(item["pattern"]))
        if not match:
            continue
        value = match.group(1).strip()
        if IP_PATTERN.fullmatch(value):
            indicator_type = ThreatIndicator.IndicatorType.IP
        elif HASH_PATTERN.fullmatch(value):
            indicator_type = ThreatIndicator.IndicatorType.HASH
        elif DOMAIN_PATTERN.fullmatch(value):
            indicator_type = ThreatIndicator.IndicatorType.DOMAIN
        elif str(value).startswith(("http://", "https://")):
            indicator_type = ThreatIndicator.IndicatorType.URL
        else:
            continue
        labels = item.get("labels") or []
        parsed.append(
            {
                "indicator_type": indicator_type,
                "value": value,
                "source_name": item.get("created_by_ref", "STIX Bundle"),
                "confidence": int(item.get("confidence") or 50),
                "malicious": any(
                    term in str(label).lower()
                    for label in labels
                    for term in ("malicious", "crime", "threat")
                )
                or bool(item.get("revoked") is False and labels),
                "taxonomy": {"labels": labels, "marking": item.get("marking_definition_refs", [])},
                "mitre_techniques": [
                    ref.get("external_id")
                    for ref in item.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
                ],
                "evidence": {
                    "pattern": item["pattern"],
                    "description": item.get("description", ""),
                },
            }
        )
    return parsed


def import_stix_bundle(
    organization, bundle, actor=None, source_type=ThreatIntelligenceRecord.SourceType.STIX
):
    created = 0
    for item in parse_stix_bundle(bundle):
        indicator, _ = ThreatIndicator.objects.get_or_create(
            organization=organization,
            indicator_type=item["indicator_type"],
            value=item["value"],
            defaults={"tags": item["taxonomy"].get("labels", [])},
        )
        _, was_created = ThreatIntelligenceRecord.objects.get_or_create(
            organization=organization,
            indicator=indicator,
            source_name=item["source_name"],
            source_type=source_type,
            observed_at=timezone.now(),
            defaults={
                "confidence": min(max(item["confidence"], 0), 100),
                "malicious": item["malicious"],
                "taxonomy": item["taxonomy"],
                "mitre_techniques": item["mitre_techniques"],
                "evidence": item["evidence"],
            },
        )
        if was_created:
            created += 1
    log_action(
        organization,
        actor,
        "threat_intelligence.imported",
        "ThreatIntelligenceRecord",
        "",
        {
            "source_type": source_type,
            "created": created,
        },
    )
    return created


def import_taxii_feed(organization, actor=None):
    if not settings.TAXII_ENABLED or not settings.TAXII_URL or not settings.TAXII_COLLECTION:
        return {"status": "NOT_CONFIGURED", "created": 0, "detail": "TAXII is not configured."}
    url = f"{settings.TAXII_URL.rstrip('/')}/collections/{settings.TAXII_COLLECTION}/objects/"
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/stix+json;version=2.1"},
            timeout=settings.TAXII_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        created = import_stix_bundle(
            organization,
            response.json(),
            actor,
            source_type=ThreatIntelligenceRecord.SourceType.TAXII,
        )
        return {"status": "OK", "created": created, "detail": "TAXII objects imported."}
    except Exception as exc:
        log_action(
            organization, actor, "threat_intelligence.taxii_failed", "", "", {"error": str(exc)}
        )
        return {"status": "ERROR", "created": 0, "detail": str(exc)}
