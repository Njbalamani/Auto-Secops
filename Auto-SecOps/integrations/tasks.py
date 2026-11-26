from celery import shared_task
from django.contrib.auth import get_user_model

from integrations.status import sync_opencti, sync_wazuh
from intelligence.enrichment import import_taxii_feed
from organizations.models import Organization

User = get_user_model()


def _actor(user_id):
    if not user_id:
        return None
    return User.objects.filter(id=user_id).first()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def sync_wazuh_task(self, organization_id, user_id=None):
    if not Organization.objects.filter(id=organization_id).exists():
        return {"status": "NOT_FOUND", "organization_id": organization_id}
    result = sync_wazuh(Organization.objects.get(id=organization_id), _actor(user_id))
    result["task_id"] = self.request.id
    return result


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def sync_opencti_task(self, organization_id, user_id=None):
    if not Organization.objects.filter(id=organization_id).exists():
        return {"status": "NOT_FOUND", "organization_id": organization_id}
    result = sync_opencti(Organization.objects.get(id=organization_id), _actor(user_id))
    result["task_id"] = self.request.id
    return result


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def poll_taxii_task(self, organization_id, user_id=None):
    if not Organization.objects.filter(id=organization_id).exists():
        return {"status": "NOT_FOUND", "organization_id": organization_id}
    result = import_taxii_feed(Organization.objects.get(id=organization_id), _actor(user_id))
    result["task_id"] = self.request.id
    return result
