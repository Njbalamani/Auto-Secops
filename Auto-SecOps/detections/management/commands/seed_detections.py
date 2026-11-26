from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from detections.definitions import SYNTHETIC_DETECTION_RULES
from detections.models import DetectionHit, DetectionRule
from detections.services import evaluate_all
from organizations.models import Organization

User = get_user_model()


class Command(BaseCommand):
    help = "Create synthetic detection rules and evaluate them for existing organizations."

    def add_arguments(self, parser):
        parser.add_argument("--organization", help="Optional organization slug.")
        parser.add_argument("--lookback-hours", type=int, default=168)

    def handle(self, *args, **options):
        organizations = Organization.objects.all()
        if options["organization"]:
            organizations = organizations.filter(slug=options["organization"])
        if not organizations.exists():
            self.stderr.write("No matching organizations found.")
            return
        actor = User.objects.filter(platform_role=User.PlatformRole.ADMIN).first()
        for organization in organizations:
            for definition in SYNTHETIC_DETECTION_RULES:
                DetectionRule.objects.get_or_create(
                    organization=organization,
                    rule_id=definition["rule_id"],
                    defaults={**definition, "enabled": True, "created_by": actor},
                )
            result = evaluate_all(organization, actor, options["lookback_hours"])
            self.stdout.write(
                self.style.SUCCESS(
                    f"{organization.name}: rules={result['evaluated']}, "
                    f"new_hits={result['new_hits']}, "
                    f"total_hits={DetectionHit.objects.filter(organization=organization).count()}"
                )
            )
