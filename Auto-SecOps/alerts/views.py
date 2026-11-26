import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from alerts.models import AlertSource, SecurityAlert
from alerts.normalization import ingest_payload, normalize_existing_alert
from config.ui import can_manage, organization_for_request
from incidents.services import create_incident_from_alert
from intelligence.enrichment import enrich_alert
from mlengine.services import classify_and_store


@login_required
def alert_list(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request, "alerts/list.html", {"alerts": [], "error": "No organization assigned."}
        )
    alerts = SecurityAlert.objects.filter(organization=organization).select_related(
        "source", "classification"
    )
    query = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "").strip()
    status = request.GET.get("status", "").strip()
    if query:
        alerts = alerts.filter(
            Q(title__icontains=query)
            | Q(description__icontains=query)
            | Q(source_ip__icontains=query)
            | Q(user_identity__icontains=query)
            | Q(external_id__icontains=query)
        )
    if severity:
        alerts = alerts.filter(severity=severity)
    if status:
        alerts = alerts.filter(status=status)
    alerts = alerts.order_by("-received_at")[:200]
    if request.method == "POST" and can_manage(request):
        action = request.POST.get("action")
        if action == "ingest":
            try:
                payload = json.loads(request.POST.get("payload", "{}"))
            except json.JSONDecodeError as exc:
                messages.error(request, f"Invalid JSON: {exc}")
                return redirect("alerts:alerts")
            source, _ = AlertSource.objects.get_or_create(
                organization=organization,
                name=request.POST.get("source_name", "UI Manual Import"),
                kind=AlertSource.Kind.MANUAL,
                defaults={"identifier": "ui-manual", "enabled": True},
            )
            alert, created = ingest_payload(payload, organization, source, request.user)
            if created:
                classify_and_store(alert, request.user)
                enrich_alert(alert, request.user)
                messages.success(request, "Alert ingested, classified, and enriched.")
            else:
                messages.info(request, "Duplicate alert; no new record created.")
            return redirect("alerts:alerts")
        alert = get_object_or_404(
            SecurityAlert, id=request.POST.get("alert_id"), organization=organization
        )
        if action == "normalize":
            normalize_existing_alert(alert, request.user)
            messages.success(request, "Alert normalized and correlated.")
        elif action == "classify":
            classification = classify_and_store(alert, request.user)
            messages.success(request, f"Classified as {classification.category}.")
        elif action == "enrich":
            _, findings = enrich_alert(alert, request.user)
            messages.success(request, f"Enriched {len(findings)} indicators.")
        elif action == "incident":
            incident = create_incident_from_alert(alert, request.user)
            messages.success(request, f"Created incident {incident.title}.")
        return redirect("alerts:alerts")
    return render(
        request,
        "alerts/list.html",
        {
            "alerts": alerts,
            "error": "",
            "filters": {"q": query, "severity": severity, "status": status},
            "severity_choices": SecurityAlert.Severity.choices,
            "status_choices": SecurityAlert.Status.choices,
        },
    )
