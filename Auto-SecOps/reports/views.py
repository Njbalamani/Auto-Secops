from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from config.ui import can_manage, organization_for_request
from reports.models import Report
from reports.services import generate_report


@login_required
def report_list(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request, "reports/list.html", {"reports": [], "error": "No organization assigned."}
        )
    reports = (
        Report.objects.filter(organization=organization)
        .select_related("incident", "generated_by")
        .order_by("-created_at")[:200]
    )
    if request.method == "POST" and can_manage(request):
        report_type = request.POST.get("report_type")
        incident = None
        if report_type == "INCIDENT":
            from incidents.models import SecurityIncident

            incident = SecurityIncident.objects.filter(
                id=request.POST.get("incident_id"), organization=organization
            ).first()
            if not incident:
                messages.error(request, "Incident not found in organization.")
                return redirect("reports:reports")
        try:
            report = generate_report(
                organization,
                report_type,
                request.user,
                incident,
                request.POST.get("title", ""),
            )
            messages.success(request, f"Generated {report.title}.")
        except ValueError as exc:
            messages.error(request, str(exc))
        return redirect("reports:reports")
    from incidents.models import SecurityIncident

    return render(
        request,
        "reports/list.html",
        {
            "reports": reports,
            "report_types": Report.ReportType.choices,
            "incidents": SecurityIncident.objects.filter(organization=organization).order_by(
                "-created_at"
            )[:100],
            "error": "",
        },
    )
