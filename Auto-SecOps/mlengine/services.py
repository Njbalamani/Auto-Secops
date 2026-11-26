from alerts.models import AlertClassification, SecurityAlert
from audit.services import log_action
from mlengine.classifier import classify_alert

VALID_CATEGORIES = {choice[0] for choice in SecurityAlert.Category.choices}
VALID_METHODS = {choice[0] for choice in AlertClassification.Method.choices}


def classify_and_store(alert, actor=None):
    result = classify_alert(alert)
    category = result["category"] if result["category"] in VALID_CATEGORIES else "OTHER"
    method = result["method"] if result["method"] in VALID_METHODS else "HYBRID"
    classification, _ = AlertClassification.objects.update_or_create(
        alert=alert,
        defaults={
            "category": category,
            "risk_score": result["risk_score"],
            "confidence": result["confidence"],
            "explanation": result["explanation"],
            "evidence": result["evidence"],
            "method": method,
            "model_version": result["model_version"],
        },
    )
    alert.status = SecurityAlert.Status.CLASSIFIED
    alert.save(update_fields=["status"])
    related_ids = (alert.normalized or {}).get("related_alert_ids", [])
    if related_ids:
        alert.related_alerts.add(*related_ids)
    log_action(
        alert.organization,
        actor,
        "alert.classified",
        "SecurityAlert",
        alert.id,
        {
            "category": classification.category,
            "risk_score": classification.risk_score,
            "confidence": classification.confidence,
            "method": classification.method,
        },
    )
    return classification
