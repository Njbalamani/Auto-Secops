from django.urls import path

from alerts.views import alert_list

urlpatterns = [path("", alert_list, name="alerts")]
