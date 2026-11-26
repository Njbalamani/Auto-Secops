from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from automation.engine import execute_for_alert
from config.exports import csv_response
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet
from incidents.models import IncidentAssignment, InvestigationNote, SecurityIncident
from incidents.serializers import (
    IncidentAssignmentSerializer,
    InvestigationNoteSerializer,
    SecurityIncidentSerializer,
)
from incidents.services import (
    add_investigation_note,
    assign_incident,
    change_status,
    create_incident_from_alert,
)


class SecurityIncidentViewSet(OrganizationScopedViewSet):
    queryset = SecurityIncident.objects.select_related("organization", "alert", "created_by").all()
    serializer_class = SecurityIncidentSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        if params.get("status"):
            queryset = queryset.filter(status=params["status"])
        if params.get("severity"):
            queryset = queryset.filter(severity=params["severity"])
        return queryset

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "id",
            "title",
            "severity",
            "priority",
            "status",
            "risk_score",
            "created_at",
            "acknowledged_at",
            "resolved_at",
            "mitre_techniques",
        ]
        rows = [
            [
                incident.id,
                incident.title,
                incident.severity,
                incident.priority,
                incident.status,
                incident.risk_score,
                incident.created_at.isoformat(),
                incident.acknowledged_at.isoformat() if incident.acknowledged_at else "",
                incident.resolved_at.isoformat() if incident.resolved_at else "",
                ", ".join(incident.mitre_techniques or []),
            ]
            for incident in self.get_queryset()[:10000]
        ]
        return csv_response("autosecops-incidents.csv", headers, rows)

    @action(detail=False, methods=["post"], url_path="from-alert")
    def from_alert(self, request):
        alert_id = request.data.get("alert")
        if not alert_id:
            raise ValidationError("alert is required.")
        from alerts.models import SecurityAlert

        alert = SecurityAlert.objects.filter(id=alert_id).first()
        if not alert or not (
            request.user.is_platform_admin or alert.organization_id == request.user.organization_id
        ):
            raise ValidationError("Alert not found or inaccessible.")
        incident = create_incident_from_alert(alert, request.user)
        return Response(SecurityIncidentSerializer(incident).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def assign(self, request, pk=None):
        incident = self.get_object()
        user_id = request.data.get("user")
        if not user_id:
            raise ValidationError("user is required.")
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.filter(id=user_id).first()
        if not user or not (
            request.user.is_platform_admin or user.organization_id == incident.organization_id
        ):
            raise ValidationError("User not found or inaccessible.")
        assignment = assign_incident(incident, user, request.user)
        return Response(IncidentAssignmentSerializer(assignment).data)

    @action(detail=True, methods=["post"])
    def note(self, request, pk=None):
        incident = self.get_object()
        text = request.data.get("note")
        if not text:
            raise ValidationError("note is required.")
        note = add_investigation_note(incident, request.user, text)
        return Response(InvestigationNoteSerializer(note).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="change-status")
    def change_status(self, request, pk=None):
        incident = self.get_object()
        new_status = request.data.get("status")
        valid = {choice[0] for choice in SecurityIncident.Status.choices}
        if new_status not in valid:
            raise ValidationError(f"status must be one of: {', '.join(sorted(valid))}")
        incident = change_status(incident, new_status, request.user, request.data.get("note", ""))
        return Response(SecurityIncidentSerializer(incident).data)

    @action(detail=True, methods=["post"], url_path="run-workflows")
    def run_workflows(self, request, pk=None):
        incident = self.get_object()
        alert = incident.alert
        if not alert:
            raise ValidationError("Incident has no linked alert for workflow matching.")
        executions = execute_for_alert(alert, request.user, incident)
        from automation.serializers import WorkflowExecutionSerializer

        return Response(
            WorkflowExecutionSerializer(executions, many=True).data,
            status=status.HTTP_201_CREATED,
        )


class InvestigationNoteViewSet(OrganizationScopedViewSet):
    queryset = InvestigationNote.objects.select_related("incident", "author").all()
    serializer_class = InvestigationNoteSerializer
    permission_classes = [CanManageSOC]
    organization_field = "incident__organization"


class IncidentAssignmentViewSet(OrganizationScopedViewSet):
    queryset = IncidentAssignment.objects.select_related("incident", "user", "assigned_by").all()
    serializer_class = IncidentAssignmentSerializer
    permission_classes = [CanManageSOC]
    organization_field = "incident__organization"
