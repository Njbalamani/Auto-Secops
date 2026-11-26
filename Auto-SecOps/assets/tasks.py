from celery import shared_task
from django.contrib.auth import get_user_model

from assets.services import reassess_assets
from organizations.models import Organization

User = get_user_model()


def _actor(user_id):
    if not user_id:
        return None
    return User.objects.filter(id=user_id).first()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def reassess_assets_task(self, organization_id, user_id=None):
    organization = Organization.objects.filter(id=organization_id).first()
    if not organization:
        return {"status": "NOT_FOUND", "organization_id": organization_id}
    results = reassess_assets(organization, _actor(user_id))
    return {
        "status": "OK",
        "organization_id": organization.id,
        "assessed": len(results),
        "results": results,
        "task_id": self.request.id,
    }
