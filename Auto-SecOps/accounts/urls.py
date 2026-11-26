from django.urls import path

from accounts.views import user_list

urlpatterns = [path("", user_list, name="users")]
