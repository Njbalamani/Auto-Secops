from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class PlatformRole(models.TextChoices):
        ADMIN = "ADMIN", "Administrator"
        SOC_ANALYST = "SOC_ANALYST", "SOC Analyst"
        INCIDENT_RESPONDER = "INCIDENT_RESPONDER", "Incident Responder"
        VIEWER = "VIEWER", "Viewer"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="members",
    )
    platform_role = models.CharField(
        max_length=32, choices=PlatformRole.choices, default=PlatformRole.VIEWER
    )
    display_name = models.CharField(max_length=160, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["username"]

    @property
    def is_platform_admin(self):
        return self.is_superuser or self.platform_role == self.PlatformRole.ADMIN

    @property
    def can_manage(self):
        return self.is_platform_admin or self.platform_role in {
            self.PlatformRole.SOC_ANALYST,
            self.PlatformRole.INCIDENT_RESPONDER,
        }

    @property
    def can_approve(self):
        return self.is_platform_admin or self.platform_role == self.PlatformRole.INCIDENT_RESPONDER

    def save(self, *args, **kwargs):
        self.email = self.email.strip().lower()
        if not self.display_name:
            self.display_name = self.get_full_name() or self.username
        super().save(*args, **kwargs)
