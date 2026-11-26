from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from config.ui import organization_for_request
from search.services import global_search


@login_required
def search_view(request):
    query = request.GET.get("q", "")
    organization = organization_for_request(request)
    results = (
        global_search(organization, query, request.GET.get("limit", 8))
        if organization
        else {
            "query": query,
            "count": 0,
            "groups": [],
        }
    )
    return render(
        request,
        "search/results.html",
        {
            "results": results,
            "error": "" if organization else "No organization assigned.",
        },
    )
