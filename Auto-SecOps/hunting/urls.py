from django.urls import path

from hunting.views import workbench

app_name = "hunting"

urlpatterns = [
    path("", workbench, name="workbench"),
]
