from django.urls import path

from detections import views

app_name = "detections"

urlpatterns = [path("", views.detections_view, name="detections")]
