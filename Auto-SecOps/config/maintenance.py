from celery import shared_task
from django.contrib.auth import get_user_model

from assets.services import reassess_assets
from detections.services import evaluate_all
from organizations.models import Organization

User = get_user_model()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def run_scheduled_maintenance(self):
    actor = User.objects.filter(platform_role=User.PlatformRole.ADMIN).first()
    organizations = Organization.objects.all()
    detection_results = []
    asset_results = []
    for organization in organizations:
        detection_results.append(
            {
                "organization": organization.slug,
                "new_hits": evaluate_all(organization, actor, 24)["new_hits"],
            }
        )
        asset_results.append(
            {
                "organization": organization.slug,
                "assessed": len(reassess_assets(organization, actor)),
            }
        )
    return {
        "status": "OK",
        "organizations": organizations.count(),
        "detections": detection_results,
        "assets": asset_results,
        "task_id": self.request.id,
    }
