from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse

from alerts.api import request_organization
from dashboard.metrics import get_metrics
from mlengine.classifier import model_info


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:home")
    error = ""
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username", ""),
            password=request.POST.get("password", ""),
        )
        if user:
            login(request, user)
            next_url = request.POST.get("next") or reverse("dashboard:home")
            return redirect(next_url)
        error = "Invalid username or password."
    return render(request, "login.html", {"error": error, "next": request.GET.get("next", "")})


@login_required
def logout_view(request):
    logout(request)
    return redirect("dashboard:login")


@login_required
def home(request):
    context = {"metrics": None, "model_info": model_info(), "organization_error": ""}
    try:
        organization = request_organization(request)
        context["metrics"] = get_metrics(organization)
        context["organization"] = organization
    except Exception as exc:
        context["organization_error"] = str(exc)
    return render(request, "dashboard/home.html", context)
