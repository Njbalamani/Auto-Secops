import hashlib
from collections import defaultdict
from datetime import timedelta

from django.utils import timezone

from alerts.models import AlertSource, SecurityAlert
from audit.services import log_action
from detections.models import DetectionHit, DetectionRule
from incidents.models import SecurityIncident
from intelligence.models import ThreatIntelligenceRecord


def _list_condition(conditions, key):
    value = conditions.get(key)
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).upper() for item in value]
    return [str(value).upper()]


def _alert_matches(alert, conditions):
    classification = getattr(alert, "classification", None)
    min_risk = int(conditions.get("min_risk_score") or 0)
    if min_risk and (not classification or classification.risk_score < min_risk):
        return False
    severities = _list_condition(conditions, "severities")
    if severities and alert.severity not in severities:
        return False
    categories = _list_condition(conditions, "categories")
    if categories and (not classification or classification.category not in categories):
        return False
    title_contains = str(conditions.get("title_contains") or "").lower()
    if title_contains and title_contains not in alert.title.lower():
        return False
    description_contains = str(conditions.get("description_contains") or "").lower()
    if description_contains and description_contains not in alert.description.lower():
        return False
    source_ips = [str(item) for item in (conditions.get("source_ips") or [])]
    if source_ips and alert.source_ip not in source_ips:
        return False
    alert_types = _list_condition(conditions, "alert_types")
    if alert_types and alert.alert_type.upper() not in alert_types:
        return False
    user_contains = str(conditions.get("user_identity_contains") or "").lower()
    if user_contains and user_contains not in alert.user_identity.lower():
        return False
    require_classification = bool(conditions.get("require_classification"))
    if require_classification and not classification:
        return False
    return True


def _create_hit(rule, fingerprint, title, summary, evidence, actor=None):
    hit, created = DetectionHit.objects.get_or_create(
        organization=rule.organization,
        fingerprint=fingerprint,
        defaults={
            "rule": rule,
            "title": title[:240],
            "summary": summary,
            "severity": rule.severity,
            "status": DetectionHit.Status.NEW,
            "evidence": evidence,
        },
    )
    if created:
        log_action(
            rule.organization,
            actor,
            "detection.hit_created",
            "DetectionHit",
            hit.id,
            {"rule": rule.rule_id, "severity": rule.severity},
        )
    return hit, created


def evaluate_single_rule(rule, organization, lookback_hours, actor=None):
    since = timezone.now() - timedelta(hours=lookback_hours)
    alerts = SecurityAlert.objects.filter(
        organization=organization, received_at__gte=since
    ).select_related("source", "classification")
    conditions = rule.conditions or {}
    created = 0
    for alert in alerts:
        if not _alert_matches(alert, conditions):
            continue
        classification = getattr(alert, "classification", None)
        evidence = {
            "alert_id": alert.id,
            "external_id": alert.external_id,
            "title": alert.title,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "user_identity": alert.user_identity,
            "event_at": alert.event_at.isoformat(),
            "category": classification.category if classification else "",
            "risk_score": classification.risk_score if classification else 0,
        }
        _, was_created = _create_hit(
            rule,
            f"rule-{rule.id}-alert-{alert.id}",
            f"{rule.name}: {alert.title}",
            rule.description,
            evidence,
            actor,
        )
        created += int(was_created)
    return created


def evaluate_correlation_rule(rule, organization, lookback_hours, actor=None):
    since = timezone.now() - timedelta(hours=lookback_hours)
    conditions = rule.conditions or {}
    group_by = conditions.get("group_by", "source_ip")
    if group_by not in {"source_ip", "user_identity", "alert_type"}:
        group_by = "source_ip"
    min_count = max(2, int(conditions.get("min_count") or 3))
    window_minutes = max(1, int(conditions.get("window_minutes") or 30))
    min_distinct = int(conditions.get("min_distinct_counterpart") or 0)
    alerts = (
        SecurityAlert.objects.filter(organization=organization, received_at__gte=since)
        .select_related("classification")
        .order_by("received_at")
    )
    groups = defaultdict(list)
    for alert in alerts:
        if not _alert_matches(alert, conditions):
            continue
        value = getattr(alert, group_by, "")
        if value:
            groups[str(value)].append(alert)

    created = 0
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
            bucket = alert.received_at.strftime("%Y%m%d%H%M")
            digest = hashlib.sha256(f"{group_by}:{value}:{bucket}".encode()).hexdigest()[:16]
            evidence = {
                "group_by": group_by,
                "value": value,
                "alert_ids": [item.id for item in recent],
                "counterparts": sorted(counterparts),
                "window_minutes": window_minutes,
                "detected_at": alert.received_at.isoformat(),
            }
            _, was_created = _create_hit(
                rule,
                f"rule-{rule.id}-corr-{digest}",
                f"{rule.name}: {group_by}={value}",
                rule.description,
                evidence,
                actor,
            )
            created += int(was_created)
    return created


def evaluate_threat_intel_rule(rule, organization, lookback_hours, actor=None):
    since = timezone.now() - timedelta(hours=lookback_hours)
    conditions = rule.conditions or {}
    min_confidence = int(conditions.get("min_confidence") or 0)
    source_types = _list_condition(conditions, "source_types")
    records = ThreatIntelligenceRecord.objects.filter(
        organization=organization, malicious=True, observed_at__gte=since
    ).select_related("indicator")
    created = 0
    for record in records:
        if min_confidence and record.confidence < min_confidence:
            continue
        if source_types and record.source_type not in source_types:
            continue
        evidence = {
            "indicator_id": record.indicator.id,
            "indicator_type": record.indicator.indicator_type,
            "value": record.indicator.value,
            "source_name": record.source_name,
            "source_type": record.source_type,
            "confidence": record.confidence,
            "observed_at": record.observed_at.isoformat(),
            "taxonomy": record.taxonomy,
        }
        _, was_created = _create_hit(
            rule,
            f"rule-{rule.id}-ti-{record.id}",
            f"{rule.name}: {record.indicator.value}",
            rule.description,
            evidence,
            actor,
        )
        created += int(was_created)
    return created


def evaluate_rule(rule, actor=None, lookback_hours=24):
    if not rule.enabled:
        return 0
    if rule.rule_type == DetectionRule.RuleType.SINGLE:
        created = evaluate_single_rule(rule, rule.organization, lookback_hours, actor)
    elif rule.rule_type == DetectionRule.RuleType.CORRELATION:
        created = evaluate_correlation_rule(rule, rule.organization, lookback_hours, actor)
    else:
        created = evaluate_threat_intel_rule(rule, rule.organization, lookback_hours, actor)
    rule.last_evaluated_at = timezone.now()
    rule.save(update_fields=["last_evaluated_at", "updated_at"])
    log_action(
        rule.organization,
        actor,
        "detection.rule_evaluated",
        "DetectionRule",
        rule.id,
        {"rule": rule.rule_id, "new_hits": created},
    )
    return created


def evaluate_all(organization, actor=None, lookback_hours=24):
    rules = DetectionRule.objects.filter(organization=organization, enabled=True)
    results = []
    for rule in rules:
        results.append(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "new_hits": evaluate_rule(rule, actor, lookback_hours),
            }
        )
    return {
        "evaluated": len(results),
        "new_hits": sum(item["new_hits"] for item in results),
        "rules": results,
    }


def review_hit(hit, status, actor=None, note=""):
    valid = {choice[0] for choice in DetectionHit.Status.choices}
    if status not in valid:
        raise ValueError(f"status must be one of: {', '.join(sorted(valid))}")
    hit.status = status
    hit.reviewer = actor
    hit.review_note = note
    hit.reviewed_at = timezone.now()
    hit.save(update_fields=["status", "reviewer", "review_note", "reviewed_at"])
    log_action(
        hit.organization,
        actor,
        "detection.hit_reviewed",
        "DetectionHit",
        hit.id,
        {"status": status, "rule": hit.rule.rule_id},
    )
    return hit


def _source_for_detections(organization):
    source, _ = AlertSource.objects.get_or_create(
        organization=organization,
        name="Detection Engine",
        kind=AlertSource.Kind.SYNTHETIC,
        defaults={"identifier": "detection-engine", "enabled": True},
    )
    return source


def create_alert_from_hit(hit, actor=None):
    from alerts.normalization import ingest_payload
    from intelligence.enrichment import enrich_alert
    from mlengine.services import classify_and_store

    if hit.alert:
        return hit.alert
    evidence = hit.evidence or {}
    payload = {
        "external_id": f"DET-{hit.id}",
        "title": hit.title,
        "description": hit.summary or f"Detection rule {hit.rule.rule_id} matched.",
        "severity": hit.severity,
        "alert_type": "detection_hit",
        "source_ip": evidence.get("source_ip") or evidence.get("value", ""),
        "user": evidence.get("user_identity", ""),
        "rule_id": hit.rule.rule_id,
        "evidence": evidence,
    }
    alert, _ = ingest_payload(
        payload, hit.organization, _source_for_detections(hit.organization), actor
    )
    classification = classify_and_store(alert, actor)
    enrich_alert(alert, actor)
    hit.alert = alert
    hit.save(update_fields=["alert"])
    log_action(
        hit.organization,
        actor,
        "detection.alert_created",
        "SecurityAlert",
        alert.id,
        {"hit_id": hit.id, "category": classification.category},
    )
    return alert


def escalate_hit(hit, actor=None, run_workflows=False, note=""):
    from automation.engine import execute_for_alert
    from incidents.services import add_investigation_note, create_incident_from_alert

    if not hit.alert:
        create_alert_from_hit(hit, actor)
    incident = hit.incident
    if not incident:
        incident = SecurityIncident.objects.filter(
            alert=hit.alert, organization=hit.organization
        ).first()
    if not incident:
        incident = create_incident_from_alert(hit.alert, actor)
        add_investigation_note(
            incident,
            actor,
            note or f"Escalated from detection rule {hit.rule.rule_id}.",
        )
    hit.incident = incident
    hit.status = DetectionHit.Status.ESCALATED
    hit.reviewer = actor
    hit.review_note = note
    hit.reviewed_at = timezone.now()
    hit.save(update_fields=["incident", "status", "reviewer", "review_note", "reviewed_at"])
    if run_workflows:
        execute_for_alert(hit.alert, actor, incident)
    log_action(
        hit.organization,
        actor,
        "detection.hit_escalated",
        "DetectionHit",
        hit.id,
        {"incident_id": incident.id, "rule": hit.rule.rule_id},
    )
    return incident
