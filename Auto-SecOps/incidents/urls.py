from django.urls import path

from incidents.views import incident_list

urlpatterns = [path("", incident_list, name="incidents")]
