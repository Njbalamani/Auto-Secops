import sys
import time
from datetime import datetime
from datetime import timezone as dt_timezone
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection

from alerts.models import SecurityAlert
from assets.models import Asset, Vulnerability
from audit.models import AuditLog
from detections.models import DetectionHit
from hunting.models import SavedHunt
from incidents.models import SecurityIncident
from integrations.status import integration_status
from mlengine.classifier import model_info

STARTED_AT = time.monotonic()


def _database_check():
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return {"name": "Database", "status": "OK", "detail": connection.vendor}
    except Exception as exc:
        return {"name": "Database", "status": "ERROR", "detail": str(exc)}


def _storage_check():
    try:
        root = Path(settings.MEDIA_ROOT)
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".autosecops-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return {"name": "Storage", "status": "OK", "detail": str(root)}
    except Exception as exc:
        return {"name": "Storage", "status": "ERROR", "detail": str(exc)}


def _static_check():
    root = Path(settings.STATIC_ROOT)
    if root.exists():
        return {"name": "Static assets", "status": "OK", "detail": str(root)}
    return {"name": "Static assets", "status": "WARNING", "detail": "Run collectstatic."}


def _broker_check():
    if settings.CELERY_TASK_ALWAYS_EAGER:
        return {"name": "Task broker", "status": "OK", "detail": "Eager mode"}
    try:
        from config.celery import app

        conn = app.broker_connection()
        conn.ensure_connection(timeout=1)
        conn.release()
        return {"name": "Task broker", "status": "OK", "detail": "Connected"}
    except Exception as exc:
        return {
            "name": "Task broker",
            "status": "OPTIONAL_UNAVAILABLE",
            "detail": str(exc)[:200] or "Broker unavailable",
        }


def system_status():
    checks = [
        _database_check(),
        _storage_check(),
        _static_check(),
        _broker_check(),
    ]
    critical_failures = [item for item in checks if item["status"] == "ERROR"]
    optional_issues = [
        item for item in checks if item["status"] in {"WARNING", "OPTIONAL_UNAVAILABLE"}
    ]
    if critical_failures:
        overall = "DEGRADED"
    elif optional_issues:
        overall = "OPERATIONAL_WITH_NOTICES"
    else:
        overall = "OPERATIONAL"
    return {
        "service": "AutoSecOps",
        "version": settings.AUTOSEOPS_VERSION,
        "deployment": settings.AUTOSEOPS_DEPLOYMENT,
        "debug": settings.DEBUG,
        "synthetic_data_only": settings.SYNTHETIC_DATA_ONLY,
        "python_version": sys.version.split()[0],
        "generated_at": datetime.now(dt_timezone.utc).isoformat(),
        "uptime_seconds": int(time.monotonic() - STARTED_AT),
        "overall": overall,
        "checks": checks,
        "counts": {
            "alerts": SecurityAlert.objects.count(),
            "incidents": SecurityIncident.objects.count(),
            "detection_hits": DetectionHit.objects.count(),
            "assets": Asset.objects.count(),
            "open_vulnerabilities": Vulnerability.objects.filter(
                status__in=[Vulnerability.Status.OPEN, Vulnerability.Status.IN_PROGRESS]
            ).count(),
            "audit_logs": AuditLog.objects.count(),
            "saved_hunts": SavedHunt.objects.count(),
            "users": get_user_model().objects.count(),
        },
        "model": model_info(),
        "integrations": integration_status(),
    }
