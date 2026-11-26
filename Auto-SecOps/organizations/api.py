from rest_framework import permissions, viewsets

from config.permissions import IsPlatformAdmin
from organizations.models import Organization
from organizations.serializers import OrganizationSerializer


class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_permissions(self):
        if self.action in {"list", "retrieve"}:
            return [permissions.IsAuthenticated()]
        return [IsPlatformAdmin()]
