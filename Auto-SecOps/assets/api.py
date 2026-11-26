from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from alerts.api import request_organization
from assets.models import Asset, AssetRiskAssessment, Vulnerability
from assets.serializers import (
    AssetRiskAssessmentSerializer,
    AssetSerializer,
    VulnerabilitySerializer,
)
from assets.services import compute_asset_risk, create_incident_for_asset, reassess_assets
from config.exports import csv_response
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet


class AssetViewSet(OrganizationScopedViewSet):
    queryset = Asset.objects.select_related("organization").all()
    serializer_class = AssetSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        if params.get("asset_type"):
            queryset = queryset.filter(asset_type=params["asset_type"])
        if params.get("criticality"):
            queryset = queryset.filter(business_criticality=params["criticality"])
        if params.get("environment"):
            queryset = queryset.filter(environment=params["environment"])
        if params.get("status"):
            queryset = queryset.filter(status=params["status"])
        if params.get("internet_exposed") in {"1", "true", "yes"}:
            queryset = queryset.filter(internet_exposed=True)
        return queryset

    @action(detail=True, methods=["post"])
    def assess(self, request, pk=None):
        asset = self.get_object()
        assessment = compute_asset_risk(asset, request.user)
        return Response(
            AssetRiskAssessmentSerializer(assessment).data, status=status.HTTP_201_CREATED
        )

    @action(detail=False, methods=["post"], url_path="reassess-all")
    def reassess_all(self, request):
        organization = request_organization(request)
        results = reassess_assets(organization, request.user)
        return Response(
            {"organization": organization.name, "assessed": len(results), "results": results}
        )

    @action(detail=True, methods=["post"], url_path="create-incident")
    def create_incident(self, request, pk=None):
        asset = self.get_object()
        incident = create_incident_for_asset(asset, request.user)
        from incidents.serializers import SecurityIncidentSerializer

        return Response(SecurityIncidentSerializer(incident).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "asset_id",
            "hostname",
            "asset_type",
            "ip_addresses",
            "owner",
            "criticality",
            "environment",
            "internet_exposed",
            "status",
            "open_vulnerabilities",
        ]
        rows = [
            [
                asset.asset_id,
                asset.hostname,
                asset.asset_type,
                ", ".join(str(value) for value in asset.ip_addresses),
                asset.owner,
                asset.business_criticality,
                asset.environment,
                asset.internet_exposed,
                asset.status,
                asset.vulnerabilities.exclude(
                    status__in=[Vulnerability.Status.REMEDIATED, Vulnerability.Status.RISK_ACCEPTED]
                ).count(),
            ]
            for asset in self.get_queryset()[:10000]
        ]
        return csv_response("autosecops-assets.csv", headers, rows)


class VulnerabilityViewSet(OrganizationScopedViewSet):
    queryset = Vulnerability.objects.select_related("organization", "asset").all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        if params.get("status"):
            queryset = queryset.filter(status=params["status"])
        if params.get("severity"):
            queryset = queryset.filter(severity=params["severity"])
        if params.get("asset"):
            queryset = queryset.filter(asset_id=params["asset"])
        return queryset

    @action(detail=True, methods=["post"], url_path="set-status")
    def set_status(self, request, pk=None):
        vulnerability = self.get_object()
        new_status = request.data.get("status")
        valid = {choice[0] for choice in Vulnerability.Status.choices}
        if new_status not in valid:
            from rest_framework.exceptions import ValidationError

            raise ValidationError(f"status must be one of: {', '.join(sorted(valid))}")
        vulnerability.status = new_status
        vulnerability.save(update_fields=["status"])
        return Response(VulnerabilitySerializer(vulnerability).data)

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "cve",
            "asset",
            "title",
            "cvss_score",
            "severity",
            "exploit_available",
            "patch_available",
            "status",
            "due_at",
        ]
        rows = [
            [
                item.cve,
                item.asset.hostname,
                item.title,
                item.cvss_score,
                item.severity,
                item.exploit_available,
                item.patch_available,
                item.status,
                item.due_at.isoformat() if item.due_at else "",
            ]
            for item in self.get_queryset()[:10000]
        ]
        return csv_response("autosecops-vulnerabilities.csv", headers, rows)


class AssetRiskAssessmentViewSet(OrganizationScopedViewSet):
    queryset = AssetRiskAssessment.objects.select_related(
        "organization", "asset", "assessed_by"
    ).all()
    serializer_class = AssetRiskAssessmentSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.query_params.get("asset"):
            queryset = queryset.filter(asset_id=self.request.query_params["asset"])
        if self.request.query_params.get("risk_level"):
            queryset = queryset.filter(risk_level=self.request.query_params["risk_level"])
        return queryset

    @action(detail=False, methods=["get"])
    def latest(self, request):
        queryset = self.get_queryset()
        latest_by_asset = {}
        for assessment in queryset.select_related("asset").order_by("assessed_at"):
            latest_by_asset[assessment.asset_id] = assessment
        data = AssetRiskAssessmentSerializer(
            sorted(latest_by_asset.values(), key=lambda item: -item.risk_score), many=True
        ).data
        return Response(data)
