from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.api import request_organization
from config.permissions import CanManageSOC
from dashboard.metrics import get_metrics
from integrations.status import integration_status


class DashboardMetricsAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        return Response(get_metrics(request_organization(request)))


class IntegrationStatusAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        return Response(integration_status())
