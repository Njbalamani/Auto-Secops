from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from config.ui import can_manage, organization_for_request
from hunting.models import SavedHunt
from hunting.services import execute_hunt, mark_hunt_run, save_hunt


@login_required
def workbench(request):
    organization = organization_for_request(request)
    if not organization:
        return render(request, "hunting/workbench.html", {"error": "No organization assigned."})

    hunts = SavedHunt.objects.filter(organization=organization).order_by("name")
    query = request.GET.get("q", "")
    result = None
    if request.method == "POST" and can_manage(request):
        action = request.POST.get("action")
        if action == "execute":
            query = request.POST.get("query", "")
            result = execute_hunt(organization, query, request.POST.get("limit", 100))
        elif action == "save":
            try:
                save_hunt(
                    organization,
                    request.user,
                    request.POST.get("name", ""),
                    request.POST.get("query", ""),
                    request.POST.get("description", ""),
                )
                messages.success(request, "Hunt saved to the library.")
            except ValueError as exc:
                messages.error(request, str(exc))
        elif action == "run-saved":
            hunt = get_object_or_404(
                SavedHunt, id=request.POST.get("hunt_id"), organization=organization
            )
            query = hunt.query
            result = execute_hunt(organization, query, 100)
            mark_hunt_run(hunt, result["summary"]["total"], request.user)
        elif action == "delete-saved":
            hunt = get_object_or_404(
                SavedHunt, id=request.POST.get("hunt_id"), organization=organization
            )
            hunt.delete()
            messages.success(request, "Saved hunt removed.")
        if action not in {"execute", "run-saved"}:
            return redirect("hunting:workbench")
    elif query:
        result = execute_hunt(organization, query, 100)

    return render(
        request,
        "hunting/workbench.html",
        {
            "query": query,
            "result": result,
            "hunts": hunts,
            "error": "",
            "can_manage_view": can_manage(request),
        },
    )
