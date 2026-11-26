from django.urls import path

from riskfabric.views import overview

app_name = "riskfabric"

urlpatterns = [
    path("", overview, name="overview"),
]
