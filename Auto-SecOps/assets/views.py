from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from assets.models import Asset, AssetRiskAssessment, Vulnerability
from assets.services import compute_asset_risk, create_incident_for_asset, reassess_assets
from config.ui import can_manage, organization_for_request


@login_required
def assets_view(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request,
            "assets/list.html",
            {
                "assets": [],
                "vulnerabilities": [],
                "latest": {},
                "error": "No organization assigned.",
            },
        )
    query = request.GET.get("q", "")
    criticality = request.GET.get("criticality", "")
    risk_level = request.GET.get("risk_level", "")
    assets = Asset.objects.filter(organization=organization).order_by("hostname")
    if query:
        assets = assets.filter(
            Q(hostname__icontains=query)
            | Q(asset_id__icontains=query)
            | Q(owner__icontains=query)
            | Q(department__icontains=query)
            | Q(description__icontains=query)
        )
    if criticality:
        assets = assets.filter(business_criticality=criticality)
    asset_ids = list(assets.values_list("id", flat=True))
    latest = {}
    for assessment in (
        AssetRiskAssessment.objects.filter(organization=organization, asset_id__in=asset_ids)
        .select_related("asset")
        .order_by("assessed_at")
    ):
        latest[assessment.asset_id] = assessment
    if risk_level:
        matching_ids = [
            asset_id
            for asset_id, assessment in latest.items()
            if assessment.risk_level == risk_level
        ]
        assets = assets.filter(id__in=matching_ids)
    vulnerabilities = (
        Vulnerability.objects.filter(organization=organization, asset_id__in=asset_ids)
        .select_related("asset")
        .order_by("-cvss_score")[:200]
    )
    assets = list(assets)
    for asset in assets:
        assessment = latest.get(asset.id)
        asset.latest_score = assessment.risk_score if assessment else None
        asset.latest_level = assessment.risk_level if assessment else "UNKNOWN"
        asset.latest_assessed_at = assessment.assessed_at if assessment else None

    if request.method == "POST" and can_manage(request):
        action = request.POST.get("action")
        if action == "reassess-all":
            results = reassess_assets(organization, request.user)
            messages.success(request, f"Reassessed {len(results)} active assets.")
        else:
            asset = get_object_or_404(
                Asset, id=request.POST.get("asset_id"), organization=organization
            )
            if action == "assess":
                assessment = compute_asset_risk(asset, request.user)
                messages.success(
                    request,
                    f"{asset.hostname} risk: {assessment.risk_level} ({assessment.risk_score}).",
                )
            elif action == "create-incident":
                incident = create_incident_for_asset(asset, request.user)
                messages.success(request, f"Created incident #{incident.id} for {asset.hostname}.")
            elif action == "set-status":
                vulnerability = get_object_or_404(
                    Vulnerability,
                    id=request.POST.get("vulnerability_id"),
                    organization=organization,
                )
                vulnerability.status = request.POST.get("status")
                vulnerability.save(update_fields=["status"])
                messages.success(request, f"{vulnerability.cve} marked {vulnerability.status}.")
        return redirect("assets:assets")
    return render(
        request,
        "assets/list.html",
        {
            "assets": assets,
            "vulnerabilities": vulnerabilities,
            "latest": latest,
            "criticalities": Asset.Criticality.choices,
            "risk_levels": AssetRiskAssessment.RiskLevel.choices,
            "vulnerability_statuses": Vulnerability.Status.choices,
            "filters": {"q": query, "criticality": criticality, "risk_level": risk_level},
            "can_manage_view": can_manage(request),
            "error": "",
        },
    )
