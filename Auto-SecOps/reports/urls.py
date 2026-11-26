from django.urls import path

from reports.views import report_list

urlpatterns = [path("", report_list, name="reports")]
