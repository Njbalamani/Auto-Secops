from celery import shared_task
from django.contrib.auth import get_user_model

from alerts.models import SecurityAlert
from alerts.normalization import ingest_payload, normalize_existing_alert
from audit.services import log_action
from intelligence.enrichment import enrich_alert
from mlengine.services import classify_and_store

User = get_user_model()


def _actor(user_id):
    if not user_id:
        return None
    return User.objects.filter(id=user_id).first()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def process_alert_task(self, alert_id, user_id=None):
    try:
        alert = SecurityAlert.objects.select_related("organization", "source").get(id=alert_id)
    except SecurityAlert.DoesNotExist:
        return {"status": "NOT_FOUND", "alert_id": alert_id}
    actor = _actor(user_id)
    if alert.status in {SecurityAlert.Status.NEW}:
        normalize_existing_alert(alert, actor)
    classification = classify_and_store(alert, actor)
    _, findings = enrich_alert(alert, actor)
    log_action(
        alert.organization,
        actor,
        "alert.async_processed",
        "SecurityAlert",
        alert.id,
        {
            "category": classification.category,
            "findings": len(findings),
            "task_id": self.request.id,
        },
    )
    return {
        "status": "OK",
        "alert_id": alert.id,
        "category": classification.category,
        "risk_score": classification.risk_score,
        "findings": len(findings),
    }


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def ingest_payload_task(self, payload, organization_id, source_id, user_id=None, auto_process=True):
    from alerts.models import AlertSource
    from organizations.models import Organization

    organization = Organization.objects.filter(id=organization_id).first()
    source = AlertSource.objects.filter(id=source_id, organization_id=organization_id).first()
    if not organization or not source:
        return {"status": "NOT_FOUND", "organization_id": organization_id, "source_id": source_id}
    alert, created = ingest_payload(payload, organization, source, _actor(user_id))
    result = {
        "status": "OK",
        "alert_id": alert.id,
        "created": created,
        "task_id": self.request.id,
    }
    if created and auto_process:
        result.update(process_alert_task(alert.id, user_id))
    return result
