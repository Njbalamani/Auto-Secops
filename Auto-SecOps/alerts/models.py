from django.db import models


class AlertSource(models.Model):
    class Kind(models.TextChoices):
        API = "API", "REST API"
        CSV = "CSV", "CSV Upload"
        WAZUH = "WAZUH", "Wazuh"
        OPENCTI = "OPENCTI", "OpenCTI"
        MANUAL = "MANUAL", "Manual"
        SYNTHETIC = "SYNTHETIC", "Synthetic"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="alert_sources"
    )
    name = models.CharField(max_length=160)
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.API)
    identifier = models.CharField(max_length=200, blank=True)
    enabled = models.BooleanField(default=True)
    config = models.JSONField(default=dict, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name", "kind"], name="uniq_alert_source_org_name_kind"
            )
        ]

    def __str__(self):
        return self.name


class SecurityAlert(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Status(models.TextChoices):
        NEW = "NEW", "New"
        NORMALIZED = "NORMALIZED", "Normalized"
        CLASSIFIED = "CLASSIFIED", "Classified"
        ENRICHED = "ENRICHED", "Enriched"
        INCIDENT = "INCIDENT", "Incident Created"
        CLOSED = "CLOSED", "Closed"
        FALSE_POSITIVE = "FALSE_POSITIVE", "False Positive"

    class Category(models.TextChoices):
        SUSPICIOUS_LOGIN = "SUSPICIOUS_LOGIN", "Suspicious Login"
        MALWARE = "MALWARE", "Malware"
        NETWORK_INTRUSION = "NETWORK_INTRUSION", "Network Intrusion"
        PHISHING = "PHISHING", "Phishing"
        PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION", "Privilege Escalation"
        OTHER = "OTHER", "Other"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="security_alerts"
    )
    source = models.ForeignKey(
        AlertSource, on_delete=models.SET_NULL, null=True, blank=True, related_name="alerts"
    )
    external_id = models.CharField(max_length=200, blank=True)
    fingerprint = models.CharField(max_length=96)
    received_at = models.DateTimeField(auto_now_add=True)
    event_at = models.DateTimeField()
    raw_payload = models.JSONField(default=dict)
    normalized = models.JSONField(default=dict, blank=True)
    source_ip = models.CharField(max_length=120, blank=True)
    destination_ip = models.CharField(max_length=120, blank=True)
    user_identity = models.CharField(max_length=200, blank=True)
    alert_type = models.CharField(max_length=120, blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    title = models.CharField(max_length=240)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    related_alerts = models.ManyToManyField("self", symmetrical=True, blank=True)

    class Meta:
        ordering = ["-received_at"]
        indexes = [
            models.Index(fields=["organization", "received_at"]),
            models.Index(fields=["organization", "severity"]),
            models.Index(fields=["organization", "status"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "fingerprint"], name="uniq_alert_org_fingerprint"
            )
        ]

    def __str__(self):
        return self.title


class AlertClassification(models.Model):
    class Method(models.TextChoices):
        RULES = "RULES", "Rules"
        ML = "ML", "Machine Learning"
        HYBRID = "HYBRID", "Hybrid"

    alert = models.OneToOneField(
        SecurityAlert, on_delete=models.CASCADE, related_name="classification"
    )
    category = models.CharField(max_length=32, choices=SecurityAlert.Category.choices)
    risk_score = models.PositiveSmallIntegerField(default=0)
    confidence = models.FloatField(default=0.0)
    explanation = models.JSONField(default=dict, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    method = models.CharField(max_length=16, choices=Method.choices, default=Method.HYBRID)
    model_version = models.CharField(max_length=80, default="hybrid-v1")
    classified_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-classified_at"]

    def __str__(self):
        return f"{self.alert.title} - {self.category}"
