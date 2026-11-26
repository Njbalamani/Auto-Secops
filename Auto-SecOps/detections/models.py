from django.conf import settings
from django.db import models


class DetectionRule(models.Model):
    class RuleType(models.TextChoices):
        SINGLE = "SINGLE", "Single Alert"
        CORRELATION = "CORRELATION", "Correlation"
        THREAT_INTEL = "THREAT_INTEL", "Threat Intelligence"

    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="detection_rules"
    )
    rule_id = models.CharField(max_length=80)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    rule_type = models.CharField(max_length=20, choices=RuleType.choices, default=RuleType.SINGLE)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    enabled = models.BooleanField(default=True)
    conditions = models.JSONField(default=dict, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_evaluated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["rule_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "rule_id"], name="uniq_detection_rule_org_rule_id"
            )
        ]

    def __str__(self):
        return f"{self.rule_id} - {self.name}"


class DetectionHit(models.Model):
    class Status(models.TextChoices):
        NEW = "NEW", "New"
        REVIEWED = "REVIEWED", "Reviewed"
        ESCALATED = "ESCALATED", "Escalated"
        DISMISSED = "DISMISSED", "Dismissed"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="detection_hits"
    )
    rule = models.ForeignKey(DetectionRule, on_delete=models.CASCADE, related_name="hits")
    fingerprint = models.CharField(max_length=180)
    title = models.CharField(max_length=240)
    summary = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=DetectionRule.Severity.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    alert = models.ForeignKey(
        "alerts.SecurityAlert",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="detection_hits",
    )
    incident = models.ForeignKey(
        "incidents.SecurityIncident",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="detection_hits",
    )
    indicator = models.ForeignKey(
        "intelligence.ThreatIndicator",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="detection_hits",
    )
    evidence = models.JSONField(default=dict, blank=True)
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_detection_hits",
    )
    review_note = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-detected_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "fingerprint"], name="uniq_detection_hit_org_fingerprint"
            )
        ]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "severity"]),
        ]

    def __str__(self):
        return self.title
