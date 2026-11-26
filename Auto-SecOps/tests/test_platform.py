import shutil
import tempfile
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from alerts.models import AlertSource, SecurityAlert
from alerts.normalization import ingest_payload
from alerts.tasks import process_alert_task
from assets.models import Asset, AssetRiskAssessment, Vulnerability
from assets.services import compute_asset_risk
from automation.models import ApprovalRequest, AutomationWorkflow, WorkflowExecution
from config.maintenance import run_scheduled_maintenance
from copilot.services import answer_question, build_briefing
from detections.backtesting import backtest_rule
from detections.models import DetectionHit, DetectionRule
from detections.services import evaluate_rule, review_hit
from hunting.models import SavedHunt
from hunting.services import execute_hunt, parse_query, save_hunt
from incidents.models import SecurityIncident
from intelligence.enrichment import import_stix_bundle
from intelligence.models import ThreatIndicator, ThreatIntelligenceRecord
from mlengine.services import classify_and_store
from organizations.models import Organization
from reports.models import Report
from reports.services import generate_report
from riskfabric.services import attack_surface_summary, build_attack_paths, forecast_risk

User = get_user_model()


@override_settings(ENABLE_SHAP_EXPLAINER=False)
class PlatformTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Test SOC", slug="test-soc", synthetic=True
        )
        self.admin = User.objects.create_user(
            username="admin",
            password="TestPass!123",
            organization=self.organization,
            platform_role=User.PlatformRole.ADMIN,
            is_staff=True,
            is_superuser=True,
        )
        self.analyst = User.objects.create_user(
            username="analyst",
            password="TestPass!123",
            organization=self.organization,
            platform_role=User.PlatformRole.SOC_ANALYST,
        )
        self.responder = User.objects.create_user(
            username="responder",
            password="TestPass!123",
            organization=self.organization,
            platform_role=User.PlatformRole.INCIDENT_RESPONDER,
        )
        self.source = AlertSource.objects.create(
            organization=self.organization,
            name="Test Source",
            kind=AlertSource.Kind.SYNTHETIC,
            identifier="test-source",
        )
        self.api = APIClient()
        self.api.force_authenticate(self.analyst)

    def _malicious_ip_intel(self, value="203.0.113.10"):
        indicator, _ = ThreatIndicator.objects.get_or_create(
            organization=self.organization,
            indicator_type=ThreatIndicator.IndicatorType.IP,
            value=value,
        )
        ThreatIntelligenceRecord.objects.create(
            organization=self.organization,
            indicator=indicator,
            source_name="Test Feed",
            malicious=True,
            confidence=95,
            observed_at=timezone.now(),
        )
        return indicator

    def test_health_endpoints(self):
        self.assertEqual(self.client.get("/health/live/").status_code, 200)
        self.assertEqual(self.client.get("/health/ready/").status_code, 200)
        status = self.client.get("/health/integrations/").json()
        self.assertEqual(status["mode"], "LOCAL_DEMO")

    def test_jwt_authentication_flow(self):
        client = APIClient()
        response = client.post(
            "/api/auth/token/",
            {"username": "analyst", "password": "TestPass!123"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.json())
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.json()['access']}")
        me = client.get("/api/auth/me/")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], "analyst")

    def test_ingestion_deduplication_classification_and_enrichment(self):
        self._malicious_ip_intel()
        payload = {
            "external_id": "TEST-001",
            "title": "Repeated failed password attempts",
            "severity": "HIGH",
            "source_ip": "203.0.113.10",
            "user": "alice",
            "description": "failed password brute force login attempts",
        }
        response = self.api.post(
            "/api/alerts/ingest/",
            {"payload": payload, "auto_process": True},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["created"], 1)
        alert = SecurityAlert.objects.get(external_id="TEST-001")
        self.assertEqual(alert.status, SecurityAlert.Status.ENRICHED)
        self.assertTrue(hasattr(alert, "classification"))
        self.assertGreater(alert.classification.risk_score, 0)
        self.assertTrue(
            any(
                item.get("malicious")
                for item in alert.classification.evidence.get("enrichment", [])
            )
        )

        duplicate = self.api.post(
            "/api/alerts/ingest/",
            {"payload": payload, "auto_process": False},
            format="json",
        )
        self.assertEqual(duplicate.json()["duplicates"], 1)
        self.assertEqual(SecurityAlert.objects.filter(external_id="TEST-001").count(), 1)

    def test_incident_workflow_and_approval_safety(self):
        self._malicious_ip_intel()
        payload = {
            "external_id": "TEST-WORKFLOW",
            "title": "Malware beacon detected",
            "severity": "CRITICAL",
            "source_ip": "203.0.113.10",
            "description": "malware command and control beacon observed",
        }
        alert, _ = ingest_payload(payload, self.organization, self.source, self.analyst)
        from intelligence.enrichment import enrich_alert
        from mlengine.services import classify_and_store

        classify_and_store(alert, self.analyst)
        enrich_alert(alert, self.analyst)

        workflow = AutomationWorkflow.objects.create(
            organization=self.organization,
            name="Block malicious source",
            conditions={"min_risk_score": 0, "require_malicious_indicator": True},
            actions=[{"type": "block_ip", "params": {"address": "203.0.113.10"}}],
            requires_approval=True,
            created_by=self.admin,
        )
        self.assertTrue(workflow.enabled)

        incident_response = self.api.post(
            f"/api/alerts/{alert.id}/create-incident/", {}, format="json"
        )
        self.assertEqual(incident_response.status_code, 201)
        incident_id = incident_response.json()["id"]

        executions_response = self.api.post(
            f"/api/incidents/{incident_id}/run-workflows/", {}, format="json"
        )
        self.assertEqual(executions_response.status_code, 201)
        self.assertEqual(len(executions_response.json()), 1)

        approval = ApprovalRequest.objects.get(organization=self.organization)
        self.assertEqual(approval.status, ApprovalRequest.Status.PENDING)
        execution = WorkflowExecution.objects.get(id=approval.execution_id)
        self.assertEqual(execution.status, WorkflowExecution.Status.PENDING_APPROVAL)
        self.assertTrue(
            all(result.get("infrastructure_changed") is False for result in execution.results)
        )

        responder_api = APIClient()
        responder_api.force_authenticate(self.responder)
        decision = responder_api.post(
            f"/api/approvals/{approval.id}/decide/",
            {"approved": True, "note": "Approved for demonstration only."},
            format="json",
        )
        self.assertEqual(decision.status_code, 200)
        approval.refresh_from_db()
        execution.refresh_from_db()
        self.assertEqual(approval.status, ApprovalRequest.Status.APPROVED)
        self.assertEqual(execution.status, WorkflowExecution.Status.COMPLETED)
        self.assertTrue(
            any(result.get("status") == "APPROVED_RECORDED" for result in execution.results)
        )
        self.assertEqual(SecurityIncident.objects.filter(organization=self.organization).count(), 1)

    def test_dashboard_metrics_are_database_backed(self):
        self._malicious_ip_intel()
        payload = {
            "external_id": "TEST-METRICS",
            "title": "Port scan detected",
            "severity": "MEDIUM",
            "source_ip": "203.0.113.10",
            "description": "network intrusion port scan",
        }
        alert, _ = ingest_payload(payload, self.organization, self.source, self.analyst)
        from mlengine.services import classify_and_store

        classify_and_store(alert, self.analyst)
        response = self.api.get("/api/dashboard/metrics/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["cards"]["total_alerts"], 1)
        self.assertEqual(data["charts"]["severities"][0]["value"], 1)
        self.assertTrue(data["charts"]["categories"])

    def test_stix_import_and_report_generation(self):
        created = import_stix_bundle(
            self.organization,
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "pattern": "[ipv4-addr:value = '198.51.100.77']",
                        "labels": ["malicious"],
                        "confidence": 88,
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1110"}
                        ],
                    }
                ],
            },
            self.analyst,
        )
        self.assertEqual(created, 1)
        self.assertEqual(
            ThreatIntelligenceRecord.objects.filter(organization=self.organization).count(), 1
        )
        temp_dir = tempfile.mkdtemp()
        try:
            with override_settings(MEDIA_ROOT=temp_dir):
                report = generate_report(
                    self.organization,
                    Report.ReportType.EXECUTIVE,
                    self.analyst,
                )
                self.assertTrue(report.pdf.name.startswith("reports/"))
                self.assertEqual(Report.objects.count(), 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_model_info_endpoint_reports_real_classifier_state(self):
        response = self.api.get("/api/ml/model-info/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["model_version"])
        self.assertGreater(data["training_examples"], 0)
        self.assertGreater(data["vocabulary_size"], 0)
        self.assertEqual(len(data["categories"]), 6)

    def test_csv_exports_respect_organization_scoping(self):
        self._malicious_ip_intel()
        payload = {
            "external_id": "TEST-CSV",
            "title": "Repeated failed password attempts",
            "severity": "HIGH",
            "source_ip": "203.0.113.10",
            "description": "failed password brute force login attempts",
        }
        alert, _ = ingest_payload(payload, self.organization, self.source, self.analyst)
        from mlengine.services import classify_and_store

        classify_and_store(alert, self.analyst)

        alerts_csv = self.api.get("/api/alerts/export-csv/")
        self.assertEqual(alerts_csv.status_code, 200)
        self.assertIn("text/csv", alerts_csv["Content-Type"])
        self.assertIn("TEST-CSV", alerts_csv.content.decode())

        incidents_csv = self.api.get("/api/incidents/export-csv/")
        self.assertEqual(incidents_csv.status_code, 200)
        audit_csv = self.api.get("/api/audit-logs/export-csv/")
        self.assertEqual(audit_csv.status_code, 200)

    def test_celery_task_processes_alert_synchronously_when_called_directly(self):
        self._malicious_ip_intel()
        payload = {
            "external_id": "TEST-ASYNC",
            "title": "Malware beacon observed",
            "severity": "CRITICAL",
            "source_ip": "203.0.113.10",
            "description": "malware command and control beacon observed",
        }
        alert, _ = ingest_payload(payload, self.organization, self.source, self.analyst)
        result = process_alert_task(alert.id, self.analyst.id)
        self.assertEqual(result["status"], "OK")
        alert.refresh_from_db()
        self.assertEqual(alert.status, SecurityAlert.Status.ENRICHED)
        self.assertTrue(hasattr(alert, "classification"))

    def test_detection_engine_evaluates_reviews_and_escalates(self):
        payload = {
            "external_id": "TEST-DETECT",
            "title": "Repeated failed password attempts",
            "severity": "HIGH",
            "source_ip": "203.0.113.10",
            "user": "alice",
            "description": "failed password brute force login attempts",
            "alert_type": "authentication_failure",
        }
        alert, _ = ingest_payload(payload, self.organization, self.source, self.analyst)
        classify_and_store(alert, self.analyst)
        rule = DetectionRule.objects.create(
            organization=self.organization,
            rule_id="TEST-DET-001",
            name="Authentication brute force",
            rule_type=DetectionRule.RuleType.SINGLE,
            severity=DetectionRule.Severity.HIGH,
            conditions={"alert_types": ["authentication_failure"], "min_risk_score": 0},
            created_by=self.admin,
        )
        self.assertEqual(evaluate_rule(rule, self.analyst), 1)
        hit = DetectionHit.objects.get(rule=rule)
        self.assertEqual(hit.status, DetectionHit.Status.NEW)
        self.assertEqual(evaluate_rule(rule, self.analyst), 0)
        self.assertEqual(DetectionHit.objects.filter(rule=rule).count(), 1)

        review_hit(hit, DetectionHit.Status.REVIEWED, self.analyst, "Confirmed synthetic hit.")
        hit.refresh_from_db()
        self.assertEqual(hit.status, DetectionHit.Status.REVIEWED)
        self.assertEqual(hit.review_note, "Confirmed synthetic hit.")

        escalation = self.api.post(f"/api/detection-hits/{hit.id}/escalate/", {}, format="json")
        self.assertEqual(escalation.status_code, 201)
        hit.refresh_from_db()
        self.assertEqual(hit.status, DetectionHit.Status.ESCALATED)
        self.assertTrue(hit.incident_id)
        self.assertEqual(SecurityIncident.objects.filter(organization=self.organization).count(), 1)

    def test_correlation_detection_exports_and_ui(self):
        for index, user in enumerate(("alice", "bob"), start=1):
            payload = {
                "external_id": f"TEST-CORR-{index}",
                "title": f"Port scan observation {index}",
                "severity": "MEDIUM",
                "source_ip": "203.0.113.44",
                "user": user,
                "description": "network intrusion port scan against multiple hosts",
                "alert_type": "nids",
            }
            ingest_payload(payload, self.organization, self.source, self.analyst)
        rule = DetectionRule.objects.create(
            organization=self.organization,
            rule_id="TEST-DET-002",
            name="Repeated source activity",
            rule_type=DetectionRule.RuleType.CORRELATION,
            severity=DetectionRule.Severity.HIGH,
            conditions={
                "group_by": "source_ip",
                "min_count": 2,
                "window_minutes": 60,
                "min_distinct_counterpart": 2,
            },
            created_by=self.admin,
        )
        self.assertEqual(evaluate_rule(rule, self.analyst), 1)
        hit = DetectionHit.objects.get(rule=rule)
        self.assertGreaterEqual(len(hit.evidence["alert_ids"]), 2)
        self.assertEqual(len(hit.evidence["counterparts"]), 2)

        csv_response = self.api.get("/api/detection-hits/export-csv/")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn("TEST-DET-002", csv_response.content.decode())
        rules_csv = self.api.get("/api/detection-rules/export-csv/")
        self.assertEqual(rules_csv.status_code, 200)
        self.assertIn("TEST-DET-002", rules_csv.content.decode())

        metrics = self.api.get("/api/dashboard/metrics/").json()
        self.assertEqual(metrics["cards"]["new_detection_hits"], 1)
        self.assertEqual(metrics["cards"]["enabled_detection_rules"], 1)
        self.assertTrue(metrics["recent_detection_hits"])

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        response = self.client.get(reverse("detections:detections"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Detection Engineering")
        self.assertContains(response, "Repeated source activity")

    def test_seed_command_creates_detection_rules_and_hits(self):
        temp_dir = tempfile.mkdtemp()
        try:
            with override_settings(MEDIA_ROOT=temp_dir):
                call_command("seed_autosecops", stdout=StringIO(), password="TestPass!123")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        seeded_org = Organization.objects.get(slug="synthetic-soc-demo")
        self.assertEqual(DetectionRule.objects.filter(organization=seeded_org).count(), 5)
        self.assertGreater(DetectionHit.objects.filter(organization=seeded_org).count(), 0)
        self.assertEqual(Asset.objects.filter(organization=seeded_org).count(), 5)
        self.assertEqual(Vulnerability.objects.filter(organization=seeded_org).count(), 6)
        self.assertGreater(AssetRiskAssessment.objects.filter(organization=seeded_org).count(), 0)
        self.assertEqual(SavedHunt.objects.filter(organization=seeded_org).count(), 3)

    def test_asset_risk_scoring_incident_and_exports(self):
        self._malicious_ip_intel()
        asset = Asset.objects.create(
            organization=self.organization,
            asset_id="AST-TEST-001",
            hostname="web-test-01",
            ip_addresses=["203.0.113.10"],
            business_criticality=Asset.Criticality.CRITICAL,
            environment=Asset.Environment.PRODUCTION,
            internet_exposed=True,
            owner="Test Web Team",
        )
        Vulnerability.objects.create(
            organization=self.organization,
            asset=asset,
            cve="CVE-2026-TEST-1",
            title="Critical test vulnerability",
            cvss_score="9.8",
            severity=Vulnerability.Severity.CRITICAL,
            exploit_available=True,
        )
        alert, _ = ingest_payload(
            {
                "external_id": "TEST-ASSET-RISK",
                "title": "Malware beacon on web server",
                "severity": "CRITICAL",
                "source_ip": "203.0.113.10",
                "description": "malware command and control beacon",
            },
            self.organization,
            self.source,
            self.analyst,
        )
        classify_and_store(alert, self.analyst)

        assessment = compute_asset_risk(asset, self.analyst)
        self.assertEqual(assessment.risk_level, AssetRiskAssessment.RiskLevel.CRITICAL)
        self.assertEqual(assessment.risk_score, 100)
        self.assertTrue(assessment.factors)
        self.assertTrue(assessment.contributing_indicators)
        self.assertTrue(assessment.contributing_alerts)

        api_assessment = self.api.post(f"/api/assets/{asset.id}/assess/", {}, format="json")
        self.assertEqual(api_assessment.status_code, 201)
        self.assertEqual(
            api_assessment.json()["risk_level"], AssetRiskAssessment.RiskLevel.CRITICAL
        )

        incident_response = self.api.post(
            f"/api/assets/{asset.id}/create-incident/", {}, format="json"
        )
        self.assertEqual(incident_response.status_code, 201)
        self.assertEqual(incident_response.json()["severity"], "CRITICAL")

        asset_csv = self.api.get("/api/assets/export-csv/")
        self.assertEqual(asset_csv.status_code, 200)
        self.assertIn("web-test-01", asset_csv.content.decode())
        vulnerability_csv = self.api.get("/api/vulnerabilities/export-csv/")
        self.assertIn("CVE-2026-TEST-1", vulnerability_csv.content.decode())
        latest = self.api.get("/api/risk-assessments/latest/")
        self.assertEqual(latest.status_code, 200)
        self.assertGreaterEqual(len(latest.json()), 1)

        metrics = self.api.get("/api/dashboard/metrics/").json()
        self.assertEqual(metrics["cards"]["total_assets"], 1)
        self.assertEqual(metrics["cards"]["critical_risk_assets"], 1)
        self.assertEqual(metrics["cards"]["open_vulnerabilities"], 1)
        self.assertEqual(metrics["cards"]["exploitable_vulnerabilities"], 1)

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        ui = self.client.get(reverse("assets:assets"))
        self.assertEqual(ui.status_code, 200)
        self.assertContains(ui, "Asset Risk")
        self.assertContains(ui, "web-test-01")

    def test_global_search_api_and_ui(self):
        ingest_payload(
            {
                "external_id": "TEST-SEARCH-001",
                "title": "Searchable suspicious login",
                "severity": "HIGH",
                "source_ip": "203.0.113.90",
                "description": "synthetic search validation",
            },
            self.organization,
            self.source,
            self.analyst,
        )
        response = self.api.get("/api/search/?q=TEST-SEARCH-001")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["query"], "TEST-SEARCH-001")
        alert_group = next(group for group in data["groups"] if group["label"] == "Alerts")
        self.assertTrue(
            any(item["title"] == "Searchable suspicious login" for item in alert_group["items"])
        )

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        page = self.client.get("/search/?q=TEST-SEARCH-001")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Global Search")
        self.assertContains(page, "Searchable suspicious login")

    def test_system_status_api_and_ui(self):
        response = self.api.get("/api/system/status/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["service"], "AutoSecOps")
        self.assertTrue(data["version"])
        self.assertIn(data["overall"], {"OPERATIONAL", "OPERATIONAL_WITH_NOTICES", "DEGRADED"})
        self.assertTrue(data["checks"])
        self.assertIn("alerts", data["counts"])

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        page = self.client.get("/system/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "System Status")
        self.assertContains(page, "Service checks")

    def test_scheduled_maintenance_task_evaluates_detections_and_assets(self):
        ingest_payload(
            {
                "external_id": "TEST-MAINTENANCE",
                "title": "Maintenance validation alert",
                "severity": "MEDIUM",
                "source_ip": "203.0.113.91",
                "description": "synthetic maintenance validation",
            },
            self.organization,
            self.source,
            self.analyst,
        )
        DetectionRule.objects.create(
            organization=self.organization,
            rule_id="TEST-DET-MAINT",
            name="Maintenance rule",
            rule_type=DetectionRule.RuleType.SINGLE,
            severity=DetectionRule.Severity.LOW,
            conditions={},
            created_by=self.admin,
        )
        asset = Asset.objects.create(
            organization=self.organization,
            asset_id="AST-MAINT-001",
            hostname="maintenance-host",
            ip_addresses=["203.0.113.91"],
            business_criticality=Asset.Criticality.HIGH,
        )
        Vulnerability.objects.create(
            organization=self.organization,
            asset=asset,
            cve="CVE-2026-MAINT",
            title="Maintenance vulnerability",
            cvss_score="7.0",
            severity=Vulnerability.Severity.HIGH,
        )

        result = run_scheduled_maintenance()
        self.assertEqual(result["status"], "OK")
        self.assertGreaterEqual(result["organizations"], 1)
        self.assertGreater(DetectionHit.objects.filter(organization=self.organization).count(), 0)
        self.assertGreater(
            AssetRiskAssessment.objects.filter(organization=self.organization).count(), 0
        )

    def test_structured_hunt_saved_hunt_api_and_ui(self):
        ingest_payload(
            {
                "external_id": "TEST-HUNT-001",
                "title": "Structured hunt target",
                "severity": "HIGH",
                "source_ip": "198.51.100.23",
                "description": "synthetic structured hunt validation",
            },
            self.organization,
            self.source,
            self.analyst,
        )
        filters, terms = parse_query('severity:HIGH type:alert ip:198.51.100 "hunt target"')
        self.assertEqual(filters["severity"], ["high"])
        self.assertIn("hunt target", terms)
        result = execute_hunt(self.organization, "severity:HIGH type:alert TEST-HUNT-001")
        self.assertGreaterEqual(result["summary"]["total"], 1)
        alert_group = next(group for group in result["groups"] if group["label"] == "Alerts")
        self.assertTrue(
            any(item["title"] == "Structured hunt target" for item in alert_group["items"])
        )

        hunt, created = save_hunt(
            self.organization, self.analyst, "HUNT-LIBRARY", "severity:HIGH TEST-HUNT-001"
        )
        self.assertTrue(created)
        self.assertEqual(hunt.created_by, self.analyst)

        api_result = self.api.post(
            "/api/hunting/execute/", {"query": "TEST-HUNT-001"}, format="json"
        )
        self.assertEqual(api_result.status_code, 200)
        self.assertGreaterEqual(api_result.data["summary"]["total"], 1)
        saved_result = self.api.get("/api/saved-hunts/")
        self.assertEqual(saved_result.status_code, 200)
        self.assertTrue(
            any(item["name"] == "HUNT-LIBRARY" for item in saved_result.data["results"])
        )
        search_result = self.api.get("/api/search/?q=HUNT-LIBRARY")
        self.assertTrue(
            any(group["label"] == "Saved Hunts" for group in search_result.data["groups"])
        )

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        page = self.client.get("/hunting/?q=TEST-HUNT-001")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Threat Hunting Workbench")
        self.assertContains(page, "Structured hunt target")
        self.assertContains(page, "HUNT-LIBRARY")

    def test_risk_fabric_attack_paths_forecast_api_and_ui(self):
        asset = Asset.objects.create(
            organization=self.organization,
            asset_id="AST-FABRIC-001",
            hostname="fabric-host",
            ip_addresses=["198.51.100.44"],
            business_criticality=Asset.Criticality.CRITICAL,
            environment=Asset.Environment.PRODUCTION,
            internet_exposed=True,
        )
        Vulnerability.objects.create(
            organization=self.organization,
            asset=asset,
            cve="CVE-2026-FABRIC",
            title="Fabric exposure",
            cvss_score="9.0",
            severity=Vulnerability.Severity.CRITICAL,
            exploit_available=True,
        )
        ingest_payload(
            {
                "external_id": "TEST-FABRIC-ALERT",
                "title": "External activity against fabric host",
                "severity": "CRITICAL",
                "source_ip": "198.51.100.44",
                "destination_ip": "10.0.0.9",
                "description": "synthetic attack path validation",
            },
            self.organization,
            self.source,
            self.analyst,
        )

        paths = build_attack_paths(self.organization, 5)
        self.assertTrue(paths)
        self.assertEqual(paths[0]["asset"]["hostname"], "fabric-host")
        self.assertGreater(paths[0]["score"], 0)
        self.assertEqual(len(paths[0]["steps"]), 3)
        summary = attack_surface_summary(self.organization)
        self.assertGreaterEqual(summary["attack_paths"], 1)
        forecast = forecast_risk(self.organization)
        self.assertIn(forecast["trend"], {"RISING", "STABLE", "FALLING"})

        self.assertEqual(self.api.get("/api/risk-fabric/summary/").status_code, 200)
        api_paths = self.api.get("/api/risk-fabric/attack-paths/")
        self.assertEqual(api_paths.status_code, 200)
        self.assertTrue(api_paths.data)
        self.assertEqual(self.api.get("/api/risk-fabric/forecast/").status_code, 200)

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        page = self.client.get("/risk-fabric/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Risk Fabric")
        self.assertContains(page, "fabric-host")
        self.assertContains(page, "CVE-2026-FABRIC")

    def test_copilot_briefing_question_api_and_ui(self):
        asset = Asset.objects.create(
            organization=self.organization,
            asset_id="AST-COPILOT-001",
            hostname="copilot-host",
            ip_addresses=["203.0.113.77"],
            business_criticality=Asset.Criticality.HIGH,
        )
        Vulnerability.objects.create(
            organization=self.organization,
            asset=asset,
            cve="CVE-2026-COPILOT",
            title="Copilot exposure",
            cvss_score="8.0",
            severity=Vulnerability.Severity.HIGH,
            exploit_available=True,
        )
        SecurityIncident.objects.create(
            organization=self.organization,
            title="Copilot validation incident",
            severity=SecurityIncident.Severity.HIGH,
            status=SecurityIncident.Status.IN_PROGRESS,
            created_by=self.analyst,
        )

        briefing = build_briefing(self.organization, self.analyst)
        self.assertEqual(briefing["mode"], "DETERMINISTIC_DECISION_SUPPORT")
        self.assertTrue(briefing["priority_actions"])
        self.assertTrue(
            all(action["requires_human_approval"] for action in briefing["priority_actions"])
        )
        answer = answer_question(self.organization, "Show open incidents", self.analyst)
        self.assertEqual(answer["intent"], "INCIDENT_STATUS")
        self.assertIn("Copilot validation incident", answer["answer"])
        recommendation = answer_question(
            self.organization, "What should we prioritize?", self.analyst
        )
        self.assertEqual(recommendation["intent"], "RECOMMENDATIONS")

        self.assertEqual(self.api.get("/api/copilot/briefing/").status_code, 200)
        ask_response = self.api.post(
            "/api/copilot/ask/", {"question": "Show exploitable vulnerabilities"}, format="json"
        )
        self.assertEqual(ask_response.status_code, 200)
        self.assertEqual(ask_response.data["intent"], "EXPOSURE_STATUS")

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        page = self.client.get("/copilot/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Shift briefing")
        self.assertContains(page, "Analyst Copilot")
        posted = self.client.post("/copilot/", {"question": "Show open incidents"})
        self.assertContains(posted, "INCIDENT_STATUS")
        self.assertContains(posted, "Copilot validation incident")

    def test_detection_backtest_is_read_only(self):
        rule = DetectionRule.objects.create(
            organization=self.organization,
            rule_id="TEST-BACKTEST",
            name="Backtest rule",
            rule_type=DetectionRule.RuleType.SINGLE,
            severity=DetectionRule.Severity.HIGH,
            conditions={"severities": ["HIGH"]},
            created_by=self.admin,
        )
        ingest_payload(
            {
                "external_id": "TEST-BACKTEST-HIGH",
                "title": "Backtest high alert",
                "severity": "HIGH",
                "source_ip": "192.0.2.41",
                "description": "synthetic backtest validation",
            },
            self.organization,
            self.source,
            self.analyst,
        )
        ingest_payload(
            {
                "external_id": "TEST-BACKTEST-LOW",
                "title": "Backtest low alert",
                "severity": "LOW",
                "source_ip": "192.0.2.42",
                "description": "synthetic backtest validation",
            },
            self.organization,
            self.source,
            self.analyst,
        )
        before_hits = DetectionHit.objects.count()

        result = backtest_rule(rule)
        self.assertEqual(result["evaluated"], 2)
        self.assertEqual(result["matched"], 1)
        self.assertTrue(result["simulation_only"])
        self.assertEqual(DetectionHit.objects.count(), before_hits)

        api_response = self.api.post(f"/api/detection-rules/{rule.id}/backtest/", {}, format="json")
        self.assertEqual(api_response.status_code, 200)
        self.assertEqual(api_response.data["matched"], 1)
        self.assertEqual(DetectionHit.objects.count(), before_hits)

        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        ui_response = self.client.post(
            "/detections/", {"action": "backtest", "rule_id": rule.id}, follow=True
        )
        self.assertEqual(ui_response.status_code, 200)
        self.assertContains(ui_response, "Backtest:")
        self.assertEqual(DetectionHit.objects.count(), before_hits)

    def test_requires_authentication(self):
        client = APIClient()
        response = client.get("/api/dashboard/metrics/")
        self.assertEqual(response.status_code, 401)

    def test_ui_login_and_dashboard(self):
        logged_in = self.client.login(username="analyst", password="TestPass!123")
        self.assertTrue(logged_in)
        response = self.client.get(reverse("dashboard:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Security Operations Dashboard")
        self.assertContains(response, "Global Search")
        self.assertContains(response, "System Status")
        self.assertContains(response, "Threat Hunting")
        self.assertContains(response, "Risk Fabric")
        self.assertContains(response, "Analyst Copilot")
