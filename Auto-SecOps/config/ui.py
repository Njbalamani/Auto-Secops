from django.shortcuts import get_object_or_404


def organization_for_request(request):
    user = request.user
    if not user.is_authenticated:
        return None
    if user.is_platform_admin:
        organization_id = request.GET.get("organization") or request.POST.get("organization")
        if organization_id:
            from organizations.models import Organization

            return get_object_or_404(Organization, id=organization_id)
    return user.organization


def can_manage(request):
    user = request.user
    return bool(user.is_authenticated and (user.is_platform_admin or user.can_manage))


def can_approve(request):
    return bool(request.user.is_authenticated and request.user.can_approve)
