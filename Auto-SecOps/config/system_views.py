from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from config.system import system_status


@login_required
def system_status_view(request):
    return render(request, "system/status.html", {"status": system_status()})
