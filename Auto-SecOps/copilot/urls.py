from django.urls import path

from copilot.views import workspace

app_name = "copilot"

urlpatterns = [
    path("", workspace, name="workspace"),
]
