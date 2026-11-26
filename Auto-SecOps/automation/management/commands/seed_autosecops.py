from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

from alerts.models import AlertSource
from alerts.normalization import ingest_payload
from assets.seeding import seed_asset_data
from automation.engine import execute_for_alert
from automation.models import AutomationWorkflow
from detections.definitions import SYNTHETIC_DETECTION_RULES
from detections.models import DetectionRule
from detections.services import evaluate_all
from hunting.models import SavedHunt
from incidents.models import SecurityIncident
from incidents.services import (
    add_investigation_note,
    assign_incident,
    change_status,
    create_incident_from_alert,
)
from intelligence.enrichment import enrich_alert
from intelligence.models import ThreatIndicator, ThreatIntelligenceRecord
from mlengine.services import classify_and_store
from organizations.models import Organization
from reports.services import generate_report

User = get_user_model()

SYNTHETIC_INDICATORS = [
    ("IP", "203.0.113.10", "Synthetic Brute Force Set", 92),
    ("IP", "198.51.100.77", "Synthetic C2 Set", 96),
    ("DOMAIN", "evil-login-example.com", "Synthetic Phishing Set", 94),
    ("HASH", "d41d8cd98f00b204e9800998ecf8427e", "Synthetic Malware Set", 89),
]

SYNTHETIC_HUNTS = [
    (
        "High severity alerts",
        "severity:HIGH type:alert",
        "Review all high severity alert activity.",
    ),
    (
        "Critical exposures",
        "severity:CRITICAL type:vulnerability",
        "Track critical vulnerabilities with attack-path evidence.",
    ),
    (
        "C2 indicator sweep",
        "type:indicator evil-login-example.com",
        "Pivot on the synthetic command-and-control domain.",
    ),
]

SYNTHETIC_ALERTS = [
    {
        "external_id": "SYN-ALERT-001",
        "title": "Repeated failed login attempts",
        "severity": "HIGH",
        "source_ip": "203.0.113.10",
        "user": "alice",
        "description": "failed password brute force attempts against vpn gateway",
        "alert_type": "authentication_failure",
    },
    {
        "external_id": "SYN-ALERT-002",
        "title": "Malware beacon observed",
        "severity": "CRITICAL",
        "source_ip": "198.51.100.77",
        "description": "malware beacon to known command and control domain evil-login-example.com",
        "alert_type": "edr_malware",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
    },
    {
        "external_id": "SYN-ALERT-003",
        "title": "Phishing message reported",
        "severity": "HIGH",
        "user": "finance-user",
        "description": "phishing email with credential harvesting link to evil-login-example.com",
        "alert_type": "mail_security",
    },
    {
        "external_id": "SYN-ALERT-004",
        "title": "Port scan detected",
        "severity": "MEDIUM",
        "source_ip": "203.0.113.10",
        "description": "network intrusion port scan against multiple internal hosts",
        "alert_type": "nids",
    },
    {
        "external_id": "SYN-ALERT-005",
        "title": "Privileged group change",
        "severity": "CRITICAL",
        "user": "svc-deploy",
        "description": "service account added to administrators group without change ticket",
        "alert_type": "iam_audit",
    },
    {
        "external_id": "SYN-ALERT-006",
        "title": "Configuration drift",
        "severity": "LOW",
        "description": "configuration baseline deviation reported by compliance scanner",
        "alert_type": "compliance",
    },
]


class Command(BaseCommand):
    help = "Seed a complete synthetic AutoSecOps demonstration dataset."

    def add_arguments(self, parser):
        parser.add_argument(
            "--password",
            default=settings.AUTOSEOPS_PASSWORD,
            help="Password applied to seeded demonstration users.",
        )

    def handle(self, *args, **options):
        password = options["password"]
        organization, _ = Organization.objects.get_or_create(
            slug="synthetic-soc-demo",
            defaults={
                "name": "Synthetic SOC Demo",
                "industry": "Demonstration",
                "description": "Synthetic data only. Not connected to production systems.",
                "synthetic": True,
            },
        )
        admin, _ = User.objects.get_or_create(
            username="autosec_admin",
            defaults={
                "email": "admin@synthetic.invalid",
                "display_name": "AutoSecOps Administrator",
                "organization": organization,
                "platform_role": User.PlatformRole.ADMIN,
                "is_staff": True,
                "is_superuser": True,
            },
        )
        analyst, _ = User.objects.get_or_create(
            username="analyst",
            defaults={
                "email": "analyst@synthetic.invalid",
                "display_name": "SOC Analyst",
                "organization": organization,
                "platform_role": User.PlatformRole.SOC_ANALYST,
            },
        )
        responder, _ = User.objects.get_or_create(
            username="responder",
            defaults={
                "email": "responder@synthetic.invalid",
                "display_name": "Incident Responder",
                "organization": organization,
                "platform_role": User.PlatformRole.INCIDENT_RESPONDER,
            },
        )
        for user in (admin, analyst, responder):
            user.set_password(password)
            user.save()

        source, _ = AlertSource.objects.get_or_create(
            organization=organization,
            name="Synthetic Security Sensors",
            kind=AlertSource.Kind.SYNTHETIC,
            defaults={"identifier": "synthetic-sensors", "enabled": True},
        )
        source.last_seen_at = timezone.now()
        source.save(update_fields=["last_seen_at"])

        for indicator_type, value, source_name, confidence in SYNTHETIC_INDICATORS:
            indicator, _ = ThreatIndicator.objects.get_or_create(
                organization=organization,
                indicator_type=indicator_type,
                value=value,
                defaults={"tags": ["synthetic", "demo"]},
            )
            ThreatIntelligenceRecord.objects.get_or_create(
                organization=organization,
                indicator=indicator,
                source_name=source_name,
                source_type=ThreatIntelligenceRecord.SourceType.LOCAL,
                observed_at=timezone.now(),
                defaults={
                    "confidence": confidence,
                    "malicious": True,
                    "taxonomy": {"tags": ["synthetic", "malicious"]},
                    "mitre_techniques": ["T1110 - Brute Force"],
                    "evidence": {"source": "synthetic seed"},
                },
            )

        alerts = []
        for payload in SYNTHETIC_ALERTS:
            alert, created = ingest_payload(payload, organization, source, admin)
            if created:
                classify_and_store(alert, admin)
                enrich_alert(alert, admin)
            alerts.append(alert)

        incidents = []
        for alert in alerts:
            classification = getattr(alert, "classification", None)
            if not classification or classification.risk_score < 55:
                continue
            existing = SecurityIncident.objects.filter(
                alert=alert, organization=organization
            ).first()
            incident = existing or create_incident_from_alert(alert, admin)
            if incident.status == SecurityIncident.Status.NEW:
                assign_incident(incident, analyst, admin)
                add_investigation_note(
                    incident,
                    analyst,
                    "Synthetic analyst note: correlated alert with seeded threat intelligence.",
                )
                change_status(
                    incident,
                    SecurityIncident.Status.IN_PROGRESS,
                    analyst,
                    "Synthetic investigation started.",
                )
            incidents.append(incident)

        workflows = [
            {
                "name": "Triage high-risk alerts",
                "conditions": {"min_risk_score": 55},
                "actions": [{"type": "add_note", "params": {"note": "Automated triage note."}}],
                "requires_approval": False,
            },
            {
                "name": "Approve malicious IP blocking",
                "conditions": {"min_risk_score": 60, "require_malicious_indicator": True},
                "actions": [{"type": "block_ip", "params": {"duration_minutes": 60}}],
                "requires_approval": True,
            },
        ]
        for definition in workflows:
            AutomationWorkflow.objects.get_or_create(
                organization=organization,
                name=definition["name"],
                defaults={
                    "description": "Synthetic demonstration workflow.",
                    "enabled": True,
                    "conditions": definition["conditions"],
                    "actions": definition["actions"],
                    "requires_approval": definition["requires_approval"],
                    "created_by": admin,
                },
            )

        detection_rules = SYNTHETIC_DETECTION_RULES
        for definition in detection_rules:
            DetectionRule.objects.get_or_create(
                organization=organization,
                rule_id=definition["rule_id"],
                defaults={**definition, "enabled": True, "created_by": admin},
            )
        detection_results = evaluate_all(organization, admin)
        for name, query, description in SYNTHETIC_HUNTS:
            SavedHunt.objects.get_or_create(
                organization=organization,
                name=name,
                defaults={"query": query, "description": description, "created_by": admin},
            )
        asset_results = seed_asset_data(organization, admin)

        for alert in alerts:
            if getattr(alert, "classification", None) and alert.classification.risk_score >= 55:
                execute_for_alert(alert, analyst)

        generate_report(organization, "EXECUTIVE", admin)
        generate_report(organization, "THREAT_INTEL", admin)
        if incidents:
            generate_report(organization, "INCIDENT", admin, incidents[0])

        self.stdout.write(
            self.style.SUCCESS(
                "Synthetic dataset ready: "
                f"users=3, alerts={len(alerts)}, incidents={len(incidents)}, "
                f"indicators={len(SYNTHETIC_INDICATORS)}, "
                f"detection_rules={detection_results['evaluated']}, "
                f"detection_hits={detection_results['new_hits']}, "
                f"assets={asset_results['assets']}, "
                f"vulnerabilities={asset_results['vulnerabilities']}, "
                f"saved_hunts={len(SYNTHETIC_HUNTS)}"
            )
        )
        self.stdout.write(
            f"Demo password: {password} (change AUTOSEOPS_PASSWORD for any non-demo use)"
        )
        self.stdout.write(
            "Safety: automation only records approved actions; no infrastructure was modified."
        )
