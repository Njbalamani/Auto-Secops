from django.conf import settings
from django.db import models


class SavedHunt(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="saved_hunts"
    )
    name = models.CharField(max_length=180)
    query = models.TextField()
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_result_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"], name="uniq_saved_hunt_org_name"
            )
        ]

    def __str__(self):
        return self.name
