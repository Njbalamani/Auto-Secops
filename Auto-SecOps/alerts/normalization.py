import csv
import hashlib
import io
import json

from dateutil import parser as date_parser
from django.conf import settings
from django.utils import timezone

from alerts.models import SecurityAlert
from audit.services import log_action

SEVERITY_ALIASES = {
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "severe": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "med": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
    "informational": "LOW",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
}

FIELD_ALIASES = {
    "external_id": ["external_id", "id", "event_id", "alert_id", "rule_id"],
    "title": ["title", "name", "event_name", "rule_name", "signature"],
    "description": ["description", "message", "details", "summary"],
    "alert_type": ["alert_type", "type", "category", "event_type", "rule"],
    "severity": ["severity", "level", "priority", "risk", "impact"],
    "source_ip": ["source_ip", "src_ip", "client_ip", "source_address", "remote_ip"],
    "destination_ip": ["destination_ip", "dst_ip", "dest_ip", "target_ip", "server_ip"],
    "user_identity": ["user_identity", "user", "username", "account", "identity", "email"],
    "event_at": ["event_at", "timestamp", "time", "@timestamp", "date", "observed_at"],
}


def _pick(payload, aliases):
    for alias in aliases:
        value = payload.get(alias)
        if value not in (None, ""):
            return value
    return None


def _normalize_severity(value):
    if isinstance(value, int):
        value = str(min(max(value, 1), 4))
    text = str(value or "").strip().lower()
    return SEVERITY_ALIASES.get(text, "MEDIUM")


def _parse_event_at(value):
    if not value:
        return timezone.now()
    try:
        parsed = date_parser.parse(str(value))
    except (ValueError, TypeError, OverflowError):
        return timezone.now()
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def compute_fingerprint(organization_id, source_kind, source_id, normalized):
    evidence = "|".join(
        [
            str(organization_id),
            str(source_kind),
            str(source_id or ""),
            str(normalized.get("external_id") or ""),
            normalized.get("event_at").strftime("%Y%m%d%H%M") if normalized.get("event_at") else "",
            str(normalized.get("alert_type") or "").lower(),
            str(normalized.get("source_ip") or ""),
            str(normalized.get("user_identity") or "").lower(),
            str(normalized.get("title") or "").lower(),
        ]
    )
    return hashlib.sha256(evidence.encode("utf-8")).hexdigest()[:32]


def normalize_payload(payload, source=None, organization=None):
    if not isinstance(payload, dict):
        raise ValueError("Alert payload must be a JSON object.")
    normalized = {key: _pick(payload, aliases) for key, aliases in FIELD_ALIASES.items()}
    normalized["severity"] = _normalize_severity(normalized["severity"])
    normalized["event_at"] = _parse_event_at(normalized["event_at"])
    normalized["title"] = str(normalized["title"] or "Security alert")
    normalized["description"] = str(normalized["description"] or "")
    normalized["alert_type"] = str(normalized["alert_type"] or "unknown")
    normalized["user_identity"] = str(normalized["user_identity"] or "")
    normalized["source_ip"] = str(normalized["source_ip"] or "")
    normalized["destination_ip"] = str(normalized["destination_ip"] or "")
    normalized["raw_payload"] = payload
    if organization and source:
        normalized["fingerprint"] = compute_fingerprint(
            organization.id, source.kind, source.identifier, normalized
        )
    normalized["event_at"] = normalized["event_at"].isoformat()
    return normalized


def validate_uploaded_file(file_obj):
    name = (getattr(file_obj, "name", "") or "").lower()
    extension = name.rsplit(".", 1)[-1] if "." in name else ""
    allowed = {"json", "csv", "log", "txt"}
    if extension not in allowed:
        raise ValueError("Unsupported file type. Upload JSON, CSV, LOG, or TXT.")
    file_obj.seek(0, io.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(0)
    if size > settings.UPLOAD_MAX_MB * 1024 * 1024:
        raise ValueError(f"File exceeds {settings.UPLOAD_MAX_MB} MB limit.")
    if not size:
        raise ValueError("Uploaded file is empty.")
    return file_obj


def ingest_payload(payload, organization, source, actor=None):
    normalized = normalize_payload(payload, source=source, organization=organization)
    existing = SecurityAlert.objects.filter(
        organization=organization, fingerprint=normalized["fingerprint"]
    ).first()
    if existing:
        return existing, False
    event_at = normalized["event_at"]
    if isinstance(event_at, str):
        event_at = _parse_event_at(event_at)
    alert = SecurityAlert.objects.create(
        organization=organization,
        source=source,
        external_id=normalized["external_id"] or "",
        title=normalized["title"],
        description=normalized["description"],
        alert_type=normalized["alert_type"],
        severity=normalized["severity"],
        source_ip=normalized["source_ip"],
        destination_ip=normalized["destination_ip"],
        user_identity=normalized["user_identity"],
        event_at=event_at,
        raw_payload=normalized["raw_payload"],
        normalized=normalized,
        fingerprint=normalized["fingerprint"],
        status=SecurityAlert.Status.NEW,
    )
    log_action(
        organization,
        actor,
        "alert.ingested",
        "SecurityAlert",
        alert.id,
        {"source": source.name, "severity": alert.severity},
    )
    return alert, True


def ingest_csv(file_obj, organization, source, actor=None):
    validate_uploaded_file(file_obj)
    decoded = io.TextIOWrapper(file_obj, encoding="utf-8-sig", errors="replace")
    reader = csv.DictReader(decoded)
    created = 0
    duplicates = 0
    errors = []
    alert_ids = []
    for index, row in enumerate(reader, start=2):
        try:
            alert, was_created = ingest_payload(dict(row), organization, source, actor)
            if was_created:
                created += 1
                alert_ids.append(alert.id)
            else:
                duplicates += 1
        except Exception as exc:
            errors.append(f"Row {index}: {exc}")
        if index > settings.UPLOAD_MAX_ROWS + 1:
            errors.append(f"Stopped after {settings.UPLOAD_MAX_ROWS} rows.")
            break
    return {
        "created": created,
        "duplicates": duplicates,
        "errors": errors,
        "alert_ids": alert_ids,
    }


def ingest_json(file_obj, organization, source, actor=None):
    validate_uploaded_file(file_obj)
    try:
        document = json.load(file_obj)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    payloads = document.get("alerts", []) if isinstance(document, dict) else document
    if not isinstance(payloads, list) or not payloads:
        raise ValueError("JSON must contain a non-empty list of alert objects.")
    created = 0
    duplicates = 0
    errors = []
    alert_ids = []
    for index, payload in enumerate(payloads[: settings.UPLOAD_MAX_ROWS], start=1):
        try:
            alert, was_created = ingest_payload(payload, organization, source, actor)
            if was_created:
                created += 1
                alert_ids.append(alert.id)
            else:
                duplicates += 1
        except Exception as exc:
            errors.append(f"Item {index}: {exc}")
    return {
        "created": created,
        "duplicates": duplicates,
        "errors": errors,
        "alert_ids": alert_ids,
    }


def normalize_existing_alert(alert, actor=None):
    normalized = normalize_payload(
        alert.raw_payload or {},
        source=alert.source,
        organization=alert.organization,
    )
    related = SecurityAlert.objects.filter(
        organization=alert.organization,
        source_ip=alert.source_ip,
    ).exclude(id=alert.id)
    if alert.user_identity:
        related = related.filter(user_identity=alert.user_identity)
    related_ids = list(related.values_list("id", flat=True)[:25])
    normalized["related_alert_ids"] = related_ids
    alert.normalized = normalized
    alert.status = SecurityAlert.Status.NORMALIZED
    alert.save(update_fields=["normalized", "status"])
    log_action(
        alert.organization,
        actor,
        "alert.normalized",
        "SecurityAlert",
        alert.id,
        {"related_alerts": len(related_ids)},
    )
    return alert
