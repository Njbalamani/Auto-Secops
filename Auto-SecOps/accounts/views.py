from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from config.ui import can_manage, organization_for_request

User = get_user_model()


@login_required
def user_list(request):
    if not can_manage(request):
        messages.error(request, "Your role cannot manage users.")
        return redirect("dashboard:home")
    organization = organization_for_request(request)
    users = User.objects.select_related("organization").all()
    if organization and not request.user.is_platform_admin:
        users = users.filter(organization=organization)
    if request.method == "POST" and request.user.is_platform_admin:
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        role = request.POST.get("platform_role", User.PlatformRole.VIEWER)
        if username and password:
            user = User(
                username=username,
                email=request.POST.get("email", ""),
                display_name=request.POST.get("display_name", ""),
                organization_id=request.POST.get("organization")
                or (organization.id if organization else None),
                platform_role=role,
                is_staff=request.POST.get("is_staff") == "on",
            )
            user.set_password(password)
            user.save()
            messages.success(request, f"User {username} created.")
            return redirect("accounts:users")
        messages.error(request, "Username and password are required.")
    return render(
        request,
        "accounts/users.html",
        {
            "users": users,
            "organizations": __import__(
                "organizations.models", fromlist=["Organization"]
            ).Organization.objects.all(),
            "roles": User.PlatformRole.choices,
        },
    )
