from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from accounts.api import CurrentUserAPIView, RegisterAPIView, UserViewSet
from alerts.api import (
    AlertClassificationViewSet,
    AlertSourceViewSet,
    SecurityAlertViewSet,
)
from assets.api import AssetRiskAssessmentViewSet, AssetViewSet, VulnerabilityViewSet
from audit.api import AuditLogViewSet
from automation.api import (
    ApprovalRequestViewSet,
    AutomationWorkflowViewSet,
    WorkflowExecutionViewSet,
)
from config.system_api import SystemStatusAPIView
from copilot.api import CopilotAskAPIView, CopilotBriefingAPIView
from dashboard.api import DashboardMetricsAPIView, IntegrationStatusAPIView
from detections.api import DetectionHitViewSet, DetectionRuleViewSet
from hunting.api import HuntExecuteAPIView, SavedHuntViewSet
from incidents.api import (
    IncidentAssignmentViewSet,
    InvestigationNoteViewSet,
    SecurityIncidentViewSet,
)
from intelligence.api import (
    ThreatIndicatorViewSet,
    ThreatIntelligenceViewSet,
)
from mlengine.api import ModelInfoAPIView
from organizations.api import OrganizationViewSet
from reports.api import GenerateReportAPIView, ReportViewSet
from riskfabric.api import (
    AttackPathsAPIView,
    AttackSurfaceSummaryAPIView,
    RiskForecastAPIView,
)
from search.api import GlobalSearchAPIView

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("alert-sources", AlertSourceViewSet, basename="alert-source")
router.register("alerts", SecurityAlertViewSet, basename="alert")
router.register("classifications", AlertClassificationViewSet, basename="classification")
router.register("threat-indicators", ThreatIndicatorViewSet, basename="threat-indicator")
router.register("threat-intelligence", ThreatIntelligenceViewSet, basename="threat-intelligence")
router.register("incidents", SecurityIncidentViewSet, basename="incident")
router.register("incident-assignments", IncidentAssignmentViewSet, basename="incident-assignment")
router.register("investigation-notes", InvestigationNoteViewSet, basename="investigation-note")
router.register("workflows", AutomationWorkflowViewSet, basename="workflow")
router.register("workflow-executions", WorkflowExecutionViewSet, basename="workflow-execution")
router.register("approvals", ApprovalRequestViewSet, basename="approval")
router.register("reports", ReportViewSet, basename="report")
router.register("audit-logs", AuditLogViewSet, basename="audit-log")
router.register("detection-rules", DetectionRuleViewSet, basename="detection-rule")
router.register("detection-hits", DetectionHitViewSet, basename="detection-hit")
router.register("assets", AssetViewSet, basename="asset")
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register("risk-assessments", AssetRiskAssessmentViewSet, basename="risk-assessment")
router.register("saved-hunts", SavedHuntViewSet, basename="saved-hunt")

urlpatterns = [
    path("auth/register/", RegisterAPIView.as_view(), name="api-register"),
    path("auth/token/", TokenObtainPairView.as_view(), name="token-obtain-pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/me/", CurrentUserAPIView.as_view(), name="api-me"),
    path("dashboard/metrics/", DashboardMetricsAPIView.as_view(), name="api-dashboard-metrics"),
    path("integrations/status/", IntegrationStatusAPIView.as_view(), name="api-integration-status"),
    path("system/status/", SystemStatusAPIView.as_view(), name="api-system-status"),
    path("ml/model-info/", ModelInfoAPIView.as_view(), name="api-model-info"),
    path("search/", GlobalSearchAPIView.as_view(), name="api-global-search"),
    path("hunting/execute/", HuntExecuteAPIView.as_view(), name="api-hunt-execute"),
    path("risk-fabric/summary/", AttackSurfaceSummaryAPIView.as_view(), name="api-risk-summary"),
    path("risk-fabric/attack-paths/", AttackPathsAPIView.as_view(), name="api-attack-paths"),
    path("risk-fabric/forecast/", RiskForecastAPIView.as_view(), name="api-risk-forecast"),
    path("copilot/briefing/", CopilotBriefingAPIView.as_view(), name="api-copilot-briefing"),
    path("copilot/ask/", CopilotAskAPIView.as_view(), name="api-copilot-ask"),
    path("reports/generate/", GenerateReportAPIView.as_view(), name="api-report-generate"),
    path("", include(router.urls)),
]
