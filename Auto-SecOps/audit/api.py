from rest_framework import permissions
from rest_framework.decorators import action

from audit.models import AuditLog
from audit.serializers import AuditLogSerializer
from config.exports import csv_response
from config.viewsets import OrganizationScopedViewSet


class AuditLogViewSet(OrganizationScopedViewSet):
    queryset = AuditLog.objects.select_related("organization", "actor").all()
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        queryset = super().get_queryset()
        action = self.request.query_params.get("action")
        if action:
            queryset = queryset.filter(action__icontains=action)
        return queryset

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "id",
            "created_at",
            "actor",
            "action",
            "target_type",
            "target_id",
            "ip_address",
            "metadata",
        ]
        rows = [
            [
                log.id,
                log.created_at.isoformat(),
                log.actor.username if log.actor else "",
                log.action,
                log.target_type,
                log.target_id,
                log.ip_address or "",
                log.metadata,
            ]
            for log in self.get_queryset()[:10000]
        ]
        return csv_response("autosecops-audit.csv", headers, rows)
