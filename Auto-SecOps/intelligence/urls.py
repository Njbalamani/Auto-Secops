from django.urls import path

from intelligence.views import intelligence_list

urlpatterns = [path("", intelligence_list, name="intelligence")]
