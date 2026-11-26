from celery import shared_task
from django.contrib.auth import get_user_model

from detections.models import DetectionRule
from detections.services import evaluate_all, evaluate_rule
from organizations.models import Organization

User = get_user_model()


def _actor(user_id):
    if not user_id:
        return None
    return User.objects.filter(id=user_id).first()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def evaluate_detections_task(self, organization_id, user_id=None, lookback_hours=24):
    organization = Organization.objects.filter(id=organization_id).first()
    if not organization:
        return {"status": "NOT_FOUND", "organization_id": organization_id}
    result = evaluate_all(organization, _actor(user_id), lookback_hours)
    result.update({"status": "OK", "task_id": self.request.id})
    return result


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def evaluate_single_detection_task(self, rule_id, user_id=None, lookback_hours=24):
    rule = DetectionRule.objects.filter(id=rule_id).select_related("organization").first()
    if not rule:
        return {"status": "NOT_FOUND", "rule_id": rule_id}
    created = evaluate_rule(rule, _actor(user_id), lookback_hours)
    return {
        "status": "OK",
        "rule_id": rule.rule_id,
        "new_hits": created,
        "task_id": self.request.id,
    }
