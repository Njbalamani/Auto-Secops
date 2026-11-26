from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from automation.engine import execute_for_alert
from config.ui import can_manage, organization_for_request
from incidents.models import SecurityIncident
from incidents.services import add_investigation_note, assign_incident, change_status
from reports.services import generate_report

User = get_user_model()


@login_required
def incident_list(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request, "incidents/list.html", {"incidents": [], "error": "No organization assigned."}
        )
    incidents = (
        SecurityIncident.objects.filter(organization=organization)
        .select_related("alert", "created_by")
        .prefetch_related("assignments__user", "timeline", "notes")
    )
    query = request.GET.get("q", "").strip()
    status = request.GET.get("status", "").strip()
    severity = request.GET.get("severity", "").strip()
    if query:
        incidents = incidents.filter(Q(title__icontains=query) | Q(description__icontains=query))
    if status:
        incidents = incidents.filter(status=status)
    if severity:
        incidents = incidents.filter(severity=severity)
    incidents = incidents.order_by("-created_at")[:200]
    if request.method == "POST" and can_manage(request):
        incident = get_object_or_404(
            SecurityIncident, id=request.POST.get("incident_id"), organization=organization
        )
        action = request.POST.get("action")
        if action == "status":
            change_status(
                incident, request.POST.get("status"), request.user, request.POST.get("note", "")
            )
            messages.success(request, "Incident status updated.")
        elif action == "note":
            if request.POST.get("note", "").strip():
                add_investigation_note(incident, request.user, request.POST["note"])
                messages.success(request, "Investigation note added.")
        elif action == "assign":
            user = User.objects.filter(
                id=request.POST.get("user_id"), organization=organization
            ).first()
            if user:
                assign_incident(incident, user, request.user)
                messages.success(request, f"Assigned to {user.display_name}.")
            else:
                messages.error(request, "User not found in organization.")
        elif action == "workflows":
            if incident.alert:
                executions = execute_for_alert(incident.alert, request.user, incident)
                messages.success(request, f"Executed {len(executions)} matching workflow(s).")
            else:
                messages.error(request, "Incident has no linked alert.")
        elif action == "report":
            report = generate_report(
                organization,
                "INCIDENT",
                request.user,
                incident,
                request.POST.get("title", ""),
            )
            messages.success(request, f"Report generated: {report.title}")
        return redirect("incidents:incidents")
    return render(
        request,
        "incidents/list.html",
        {
            "incidents": incidents,
            "statuses": SecurityIncident.Status.choices,
            "severities": SecurityIncident.Severity.choices,
            "users": User.objects.filter(organization=organization),
            "filters": {"q": query, "status": status, "severity": severity},
            "error": "",
        },
    )
