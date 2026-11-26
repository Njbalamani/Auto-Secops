from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from audit.models import AuditLog
from config.ui import organization_for_request


@login_required
def audit_list(request):
    organization = organization_for_request(request)
    logs = AuditLog.objects.select_related("organization", "actor").order_by("-created_at")
    if organization and not request.user.is_platform_admin:
        logs = logs.filter(organization=organization)
    if request.GET.get("action"):
        logs = logs.filter(action__icontains=request.GET["action"])
    return render(request, "audit/list.html", {"logs": logs[:200], "error": ""})
