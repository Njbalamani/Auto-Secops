from django.http import JsonResponse
from django.urls import include, path

from config.system_views import system_status_view


def health_live(request):
    from django.conf import settings

    return JsonResponse(
        {
            "status": "ok",
            "service": "AutoSecOps",
            "version": settings.AUTOSEOPS_VERSION,
            "deployment": settings.AUTOSEOPS_DEPLOYMENT,
        }
    )


def health_ready(request):
    from django.db import connection

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return JsonResponse({"status": "ready", "database": "ok"})
    except Exception as exc:
        return JsonResponse({"status": "unready", "database": str(exc)}, status=503)


def health_integrations(request):
    from integrations.status import integration_status

    return JsonResponse(integration_status())


urlpatterns = [
    path("health/live/", health_live, name="health-live"),
    path("health/ready/", health_ready, name="health-ready"),
    path("health/integrations/", health_integrations, name="health-integrations"),
    path("system/", system_status_view, name="system-status"),
    path("api/", include("config.api")),
    path("", include("dashboard.urls")),
    path("accounts/", include("accounts.urls")),
    path("alerts/", include("alerts.urls")),
    path("intelligence/", include("intelligence.urls")),
    path("incidents/", include("incidents.urls")),
    path("detections/", include("detections.urls")),
    path("assets/", include("assets.urls")),
    path("automation/", include("automation.urls")),
    path("reports/", include("reports.urls")),
    path("audit/", include("audit.urls")),
    path("search/", include("search.urls")),
    path("hunting/", include("hunting.urls")),
    path("risk-fabric/", include("riskfabric.urls")),
    path("copilot/", include("copilot.urls")),
]
