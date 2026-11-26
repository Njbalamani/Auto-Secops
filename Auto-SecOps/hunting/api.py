from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.api import request_organization
from audit.services import log_action
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet
from hunting.models import SavedHunt
from hunting.serializers import SavedHuntSerializer
from hunting.services import execute_hunt, mark_hunt_run


class HuntExecuteAPIView(APIView):
    permission_classes = [CanManageSOC]

    def post(self, request):
        organization = request_organization(request)
        query = request.data.get("query", "")
        if not str(query).strip():
            raise ValidationError("query is required.")
        result = execute_hunt(organization, query, request.data.get("limit", 100))
        log_action(
            organization,
            request.user,
            "hunt.executed",
            "ThreatHunt",
            "",
            {"query": query, "results": result["summary"]["total"]},
        )
        return Response(result)

    def get(self, request):
        organization = request_organization(request)
        query = request.query_params.get("q", "")
        if not str(query).strip():
            raise ValidationError("q is required.")
        return Response(execute_hunt(organization, query, request.query_params.get("limit", 100)))


class SavedHuntViewSet(OrganizationScopedViewSet):
    queryset = SavedHunt.objects.select_related("organization", "created_by").all()
    serializer_class = SavedHuntSerializer
    permission_classes = [CanManageSOC]

    def perform_create(self, serializer):
        super().perform_create(serializer)
        hunt = serializer.instance
        hunt.created_by = self.request.user
        hunt.save(update_fields=["created_by"])
        log_action(
            hunt.organization,
            self.request.user,
            "hunt.saved",
            "SavedHunt",
            hunt.id,
            {"name": hunt.name, "query": hunt.query},
        )

    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        hunt = self.get_object()
        result = execute_hunt(hunt.organization, hunt.query, request.data.get("limit", 100))
        mark_hunt_run(hunt, result["summary"]["total"], request.user)
        return Response(result)
