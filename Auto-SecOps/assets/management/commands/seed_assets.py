from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from assets.seeding import seed_asset_data
from organizations.models import Organization

User = get_user_model()


class Command(BaseCommand):
    help = "Create synthetic assets and vulnerabilities and reassess asset risk."

    def add_arguments(self, parser):
        parser.add_argument("--organization", help="Optional organization slug.")

    def handle(self, *args, **options):
        organizations = Organization.objects.all()
        if options["organization"]:
            organizations = organizations.filter(slug=options["organization"])
        if not organizations.exists():
            self.stderr.write("No matching organizations found.")
            return
        actor = User.objects.filter(platform_role=User.PlatformRole.ADMIN).first()
        for organization in organizations:
            result = seed_asset_data(organization, actor)
            self.stdout.write(
                self.style.SUCCESS(
                    f"{organization.name}: assets={result['assets']}, "
                    f"vulnerabilities={result['vulnerabilities']}, "
                    f"reassessed={len(result['results'])}"
                )
            )
