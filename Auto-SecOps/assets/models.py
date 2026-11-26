from django.conf import settings
from django.db import models


class Asset(models.Model):
    class AssetType(models.TextChoices):
        SERVER = "SERVER", "Server"
        WORKSTATION = "WORKSTATION", "Workstation"
        NETWORK_DEVICE = "NETWORK_DEVICE", "Network Device"
        CLOUD_SERVICE = "CLOUD_SERVICE", "Cloud Service"
        APPLICATION = "APPLICATION", "Application"
        DATABASE = "DATABASE", "Database"

    class Criticality(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Environment(models.TextChoices):
        PRODUCTION = "PRODUCTION", "Production"
        STAGING = "STAGING", "Staging"
        DEVELOPMENT = "DEVELOPMENT", "Development"
        LAB = "LAB", "Lab"

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        INACTIVE = "INACTIVE", "Inactive"
        DECOMMISSIONED = "DECOMMISSIONED", "Decommissioned"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="assets"
    )
    asset_id = models.CharField(max_length=80)
    hostname = models.CharField(max_length=200)
    asset_type = models.CharField(
        max_length=24, choices=AssetType.choices, default=AssetType.SERVER
    )
    ip_addresses = models.JSONField(default=list, blank=True)
    mac_addresses = models.JSONField(default=list, blank=True)
    owner = models.CharField(max_length=160, blank=True)
    department = models.CharField(max_length=160, blank=True)
    business_criticality = models.CharField(
        max_length=16, choices=Criticality.choices, default=Criticality.MEDIUM
    )
    environment = models.CharField(
        max_length=20, choices=Environment.choices, default=Environment.PRODUCTION
    )
    internet_exposed = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    tags = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["hostname"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "asset_id"], name="uniq_asset_org_asset_id"
            )
        ]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "business_criticality"]),
        ]

    def __str__(self):
        return f"{self.hostname} ({self.asset_id})"

    @property
    def primary_ip(self):
        return self.ip_addresses[0] if self.ip_addresses else ""


class Vulnerability(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Status(models.TextChoices):
        OPEN = "OPEN", "Open"
        IN_PROGRESS = "IN_PROGRESS", "In progress"
        REMEDIATED = "REMEDIATED", "Remediated"
        RISK_ACCEPTED = "RISK_ACCEPTED", "Risk accepted"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="vulnerabilities"
    )
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="vulnerabilities")
    cve = models.CharField(max_length=40)
    title = models.CharField(max_length=240)
    description = models.TextField(blank=True)
    cvss_score = models.DecimalField(max_digits=4, decimal_places=1, default=0)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    exploit_available = models.BooleanField(default=False)
    patch_available = models.BooleanField(default=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    discovered_at = models.DateTimeField(auto_now_add=True)
    due_at = models.DateTimeField(null=True, blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-cvss_score", "cve"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "asset", "cve"], name="uniq_vulnerability_org_asset_cve"
            )
        ]
        indexes = [
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "severity"]),
        ]

    def __str__(self):
        return f"{self.cve} on {self.asset.hostname}"


class AssetRiskAssessment(models.Model):
    class RiskLevel(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="risk_assessments"
    )
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="risk_assessments")
    risk_score = models.PositiveIntegerField(default=0)
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.LOW)
    factors = models.JSONField(default=list, blank=True)
    contributing_alerts = models.JSONField(default=list, blank=True)
    contributing_hits = models.JSONField(default=list, blank=True)
    contributing_indicators = models.JSONField(default=list, blank=True)
    assessed_at = models.DateTimeField(auto_now_add=True)
    assessed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        ordering = ["-assessed_at"]
        indexes = [
            models.Index(fields=["organization", "risk_level"]),
            models.Index(fields=["asset", "assessed_at"]),
        ]

    def __str__(self):
        return f"{self.asset.hostname}: {self.risk_level} ({self.risk_score})"
