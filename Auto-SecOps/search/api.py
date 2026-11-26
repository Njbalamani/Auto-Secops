from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.api import request_organization
from config.permissions import CanManageSOC
from search.services import global_search


class GlobalSearchAPIView(APIView):
    permission_classes = [CanManageSOC]

    def get(self, request):
        query = request.query_params.get("q", "")
        limit = request.query_params.get("limit", 8)
        organization = request_organization(request)
        return Response(global_search(organization, query, limit))
