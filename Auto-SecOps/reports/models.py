from django.conf import settings
from django.db import models


class Report(models.Model):
    class ReportType(models.TextChoices):
        INCIDENT = "INCIDENT", "Incident Report"
        EXECUTIVE = "EXECUTIVE", "Executive Summary"
        THREAT_INTEL = "THREAT_INTEL", "Threat Intelligence Summary"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="reports"
    )
    title = models.CharField(max_length=220)
    report_type = models.CharField(max_length=20, choices=ReportType.choices)
    incident = models.ForeignKey(
        "incidents.SecurityIncident",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    pdf = models.FileField(upload_to="reports/", blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organization", "report_type"])]

    def __str__(self):
        return self.title
