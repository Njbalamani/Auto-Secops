from django.urls import path

from automation.views import workflow_list

urlpatterns = [path("", workflow_list, name="workflows")]
