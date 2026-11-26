from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.serializers import RegisterSerializer, UserSerializer
from config.permissions import IsPlatformAdmin
from config.viewsets import OrganizationScopedViewSet

User = get_user_model()


class RegisterAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=201)


class CurrentUserAPIView(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)


class UserViewSet(OrganizationScopedViewSet):
    queryset = User.objects.select_related("organization").all()
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action in {"list", "retrieve"}:
            return [permissions.IsAuthenticated()]
        return [IsPlatformAdmin()]

    def perform_create(self, serializer):
        password = serializer.validated_data.pop("password", None)
        user = serializer.save()
        if password:
            user.set_password(password)
            user.save(update_fields=["password"])

    def perform_update(self, serializer):
        password = serializer.validated_data.pop("password", None)
        user = serializer.save()
        if password:
            user.set_password(password)
            user.save(update_fields=["password"])

    def get_object(self):
        if self.kwargs.get("pk") == "me":
            return self.request.user
        return super().get_object()
