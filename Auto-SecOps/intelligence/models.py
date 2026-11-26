from django.db import models


class ThreatIndicator(models.Model):
    class IndicatorType(models.TextChoices):
        IP = "IP", "IP Address"
        DOMAIN = "DOMAIN", "Domain"
        HASH = "HASH", "File Hash"
        URL = "URL", "URL"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="threat_indicators"
    )
    indicator_type = models.CharField(max_length=16, choices=IndicatorType.choices)
    value = models.CharField(max_length=500)
    tags = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["value"]
        indexes = [models.Index(fields=["organization", "indicator_type", "value"])]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "indicator_type", "value"], name="uniq_indicator_org_value"
            )
        ]

    def __str__(self):
        return f"{self.indicator_type}: {self.value}"


class ThreatIntelligenceRecord(models.Model):
    class SourceType(models.TextChoices):
        LOCAL = "LOCAL", "Local Synthetic"
        STIX = "STIX", "STIX Bundle"
        TAXII = "TAXII", "TAXII Feed"
        OPENCTI = "OPENCTI", "OpenCTI"
        WAZUH = "WAZUH", "Wazuh"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="threat_intelligence",
    )
    indicator = models.ForeignKey(
        ThreatIndicator, on_delete=models.CASCADE, related_name="intelligence_records"
    )
    source_name = models.CharField(max_length=160)
    source_type = models.CharField(
        max_length=16, choices=SourceType.choices, default=SourceType.LOCAL
    )
    confidence = models.PositiveSmallIntegerField(default=50)
    malicious = models.BooleanField(default=False)
    taxonomy = models.JSONField(default=dict, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    observed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-observed_at"]
        indexes = [
            models.Index(fields=["organization", "source_type"]),
            models.Index(fields=["organization", "malicious"]),
        ]

    def __str__(self):
        return f"{self.source_name} - {self.indicator.value}"
