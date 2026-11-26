from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.api import request_organization
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet
from reports.models import Report
from reports.serializers import ReportSerializer
from reports.services import generate_report


class GenerateReportAPIView(APIView):
    permission_classes = [CanManageSOC]

    def post(self, request):
        organization = request_organization(request)
        report_type = request.data.get("report_type")
        valid = {choice[0] for choice in Report.ReportType.choices}
        if report_type not in valid:
            raise ValidationError(f"report_type must be one of: {', '.join(sorted(valid))}")
        incident = None
        if report_type == Report.ReportType.INCIDENT:
            incident_id = request.data.get("incident")
            if not incident_id:
                raise ValidationError("incident is required for incident reports.")
            from incidents.models import SecurityIncident

            incident = SecurityIncident.objects.filter(
                id=incident_id, organization=organization
            ).first()
            if not incident:
                raise ValidationError("Incident not found in organization.")
        report = generate_report(
            organization,
            report_type,
            request.user,
            incident,
            request.data.get("title", ""),
        )
        return Response(ReportSerializer(report).data, status=status.HTTP_201_CREATED)


class ReportViewSet(OrganizationScopedViewSet):
    queryset = Report.objects.select_related("organization", "incident", "generated_by").all()
    serializer_class = ReportSerializer
    permission_classes = [CanManageSOC]
