from django.conf import settings
from django.db import models


class SecurityIncident(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Priority(models.TextChoices):
        P4 = "P4", "P4 - Low"
        P3 = "P3", "P3 - Medium"
        P2 = "P2", "P2 - High"
        P1 = "P1", "P1 - Critical"

    class Status(models.TextChoices):
        NEW = "NEW", "New"
        IN_PROGRESS = "IN_PROGRESS", "In Progress"
        WAITING_APPROVAL = "WAITING_APPROVAL", "Waiting Approval"
        RESOLVED = "RESOLVED", "Resolved"
        CLOSED = "CLOSED", "Closed"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="incidents"
    )
    title = models.CharField(max_length=240)
    description = models.TextField(blank=True)
    alert = models.ForeignKey(
        "alerts.SecurityAlert",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="incidents",
    )
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    priority = models.CharField(max_length=4, choices=Priority.choices, default=Priority.P3)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    risk_score = models.PositiveSmallIntegerField(default=0)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_incidents",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "severity"]),
            models.Index(fields=["organization", "created_at"]),
        ]

    def __str__(self):
        return self.title


class IncidentAssignment(models.Model):
    incident = models.ForeignKey(
        SecurityIncident, on_delete=models.CASCADE, related_name="assignments"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="incident_assignments"
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_incidents",
    )
    active = models.BooleanField(default=True)
    assigned_at = models.DateTimeField(auto_now_add=True)
    unassigned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-assigned_at"]

    def __str__(self):
        return f"{self.user.username} - {self.incident.title}"


class InvestigationNote(models.Model):
    incident = models.ForeignKey(SecurityIncident, on_delete=models.CASCADE, related_name="notes")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    note = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Note on {self.incident.title}"


class IncidentTimeline(models.Model):
    incident = models.ForeignKey(
        SecurityIncident, on_delete=models.CASCADE, related_name="timeline"
    )
    event_type = models.CharField(max_length=80)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    summary = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["occurred_at"]

    def __str__(self):
        return f"{self.event_type} - {self.incident.title}"
