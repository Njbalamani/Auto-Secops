from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from config.ui import organization_for_request
from riskfabric.services import attack_surface_summary, build_attack_paths, forecast_risk


@login_required
def overview(request):
    organization = organization_for_request(request)
    if not organization:
        return render(request, "riskfabric/overview.html", {"error": "No organization assigned."})
    return render(
        request,
        "riskfabric/overview.html",
        {
            "summary": attack_surface_summary(organization),
            "forecast": forecast_risk(organization),
            "paths": build_attack_paths(organization, 10),
            "error": "",
        },
    )
