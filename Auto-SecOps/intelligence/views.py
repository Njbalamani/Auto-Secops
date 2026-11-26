import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from config.ui import can_manage, organization_for_request
from intelligence.enrichment import import_stix_bundle, import_taxii_feed
from intelligence.models import ThreatIndicator, ThreatIntelligenceRecord


@login_required
def intelligence_list(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request,
            "intelligence/list.html",
            {"indicators": [], "records": [], "error": "No organization assigned."},
        )
    indicators = ThreatIndicator.objects.filter(organization=organization).order_by("value")[:200]
    records = (
        ThreatIntelligenceRecord.objects.filter(organization=organization)
        .select_related("indicator")
        .order_by("-observed_at")[:200]
    )
    if request.method == "POST" and can_manage(request):
        action = request.POST.get("action")
        if action == "stix":
            try:
                bundle = json.loads(request.POST.get("bundle", "{}"))
                created = import_stix_bundle(organization, bundle, request.user)
                messages.success(request, f"Imported {created} STIX intelligence records.")
            except (json.JSONDecodeError, ValueError) as exc:
                messages.error(request, f"STIX import failed: {exc}")
        elif action == "taxii":
            result = import_taxii_feed(organization, request.user)
            messages.info(request, f"TAXII {result['status']}: {result['detail']}")
        return redirect("intelligence:intelligence")
    return render(
        request,
        "intelligence/list.html",
        {"indicators": indicators, "records": records, "error": ""},
    )
