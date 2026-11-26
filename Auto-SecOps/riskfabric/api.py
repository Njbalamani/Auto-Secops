from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.api import request_organization
from config.permissions import CanManageSOC
from riskfabric.services import attack_surface_summary, build_attack_paths, forecast_risk


class AttackSurfaceSummaryAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        return Response(attack_surface_summary(request_organization(request)))


class AttackPathsAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        organization = request_organization(request)
        limit = request.query_params.get("limit", 10)
        return Response(build_attack_paths(organization, limit))


class RiskForecastAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        organization = request_organization(request)
        days = request.query_params.get("days", 7)
        return Response(forecast_risk(organization, days))
