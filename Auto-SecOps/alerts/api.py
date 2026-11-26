from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from alerts.models import AlertClassification, AlertSource, SecurityAlert
from alerts.normalization import (
    compute_fingerprint,
    ingest_csv,
    ingest_json,
    ingest_payload,
    normalize_existing_alert,
)
from alerts.serializers import (
    AlertClassificationSerializer,
    AlertSourceSerializer,
    SecurityAlertSerializer,
)
from alerts.tasks import process_alert_task
from config.exports import csv_response
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet
from incidents.services import create_incident_from_alert
from intelligence.enrichment import enrich_alert
from mlengine.services import classify_and_store


def request_organization(request):
    user = request.user
    if user.is_platform_admin:
        organization_id = request.data.get("organization") or request.query_params.get(
            "organization"
        )
        if organization_id:
            from organizations.models import Organization

            return get_object_or_404(Organization, id=organization_id)
    if user.organization:
        return user.organization
    raise ValidationError("Assign an organization or provide an organization identifier.")


def request_source(request, organization):
    source_id = request.data.get("source") or request.query_params.get("source")
    if source_id:
        return get_object_or_404(AlertSource, id=source_id, organization=organization)
    name = request.data.get("source_name", "REST API Import")
    source, _ = AlertSource.objects.get_or_create(
        organization=organization,
        name=name,
        kind=request.data.get("source_kind", AlertSource.Kind.API),
        defaults={"identifier": name, "enabled": True},
    )
    return source


class AlertSourceViewSet(OrganizationScopedViewSet):
    queryset = AlertSource.objects.select_related("organization").all()
    serializer_class = AlertSourceSerializer
    permission_classes = [CanManageSOC]


class SecurityAlertViewSet(OrganizationScopedViewSet):
    queryset = SecurityAlert.objects.select_related("source", "classification").all()
    serializer_class = SecurityAlertSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        filters = self.request.query_params
        if filters.get("severity"):
            queryset = queryset.filter(severity=filters["severity"])
        if filters.get("status"):
            queryset = queryset.filter(status=filters["status"])
        if filters.get("category"):
            queryset = queryset.filter(classification__category=filters["category"])
        return queryset

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "id",
            "external_id",
            "title",
            "severity",
            "status",
            "source_ip",
            "user_identity",
            "category",
            "risk_score",
            "event_at",
        ]
        rows = []
        for alert in self.get_queryset().select_related("classification")[:10000]:
            classification = getattr(alert, "classification", None)
            rows.append(
                [
                    alert.id,
                    alert.external_id,
                    alert.title,
                    alert.severity,
                    alert.status,
                    alert.source_ip,
                    alert.user_identity,
                    classification.category if classification else "",
                    classification.risk_score if classification else "",
                    alert.event_at.isoformat(),
                ]
            )
        return csv_response("autosecops-alerts.csv", headers, rows)

    def perform_create(self, serializer):
        organization = request_organization(self.request)
        source = request_source(self.request, organization)
        data = serializer.validated_data
        normalized = {
            "alert_type": data.get("alert_type", ""),
            "user_identity": data.get("user_identity", ""),
            "source_ip": data.get("source_ip", ""),
            "destination_ip": data.get("destination_ip", ""),
            "event_at": data.get("event_at") or timezone.now(),
        }
        fingerprint = compute_fingerprint(
            organization.id, source.kind, source.identifier, normalized
        )
        serializer.save(
            organization=organization,
            source=source,
            raw_payload=data.get("raw_payload", {}),
            normalized=normalized,
            fingerprint=fingerprint,
        )

    @action(detail=False, methods=["post"])
    def ingest(self, request):
        organization = request_organization(request)
        source = request_source(request, organization)
        uploaded = request.FILES.get("file")
        try:
            if uploaded:
                if uploaded.name.lower().endswith(".csv"):
                    result = ingest_csv(uploaded, organization, source, request.user)
                else:
                    result = ingest_json(uploaded, organization, source, request.user)
            else:
                payload = request.data.get("payload")
                if not isinstance(payload, dict):
                    raise ValidationError("Provide a payload object or upload a JSON/CSV file.")
                alert, created = ingest_payload(payload, organization, source, request.user)
                result = {
                    "created": int(created),
                    "duplicates": int(not created),
                    "errors": [],
                    "alert_ids": [alert.id] if created else [],
                }
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        auto_process = str(request.data.get("auto_process", "true")).lower() in {
            "1",
            "true",
            "yes",
        }
        if auto_process and result.get("alert_ids"):
            alerts = SecurityAlert.objects.filter(
                id__in=result["alert_ids"], organization=organization
            ).select_related("source")
            result["classifications"] = []
            result["enriched"] = []
            for alert in alerts:
                classification = classify_and_store(alert, request.user)
                result["classifications"].append(classification.category)
                enrich_alert(alert, request.user)
                result["enriched"].append(alert.id)
        return Response(result, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def normalize(self, request, pk=None):
        alert = self.get_object()
        normalize_existing_alert(alert, request.user)
        return Response(SecurityAlertSerializer(alert).data)

    @action(detail=True, methods=["post"])
    def classify(self, request, pk=None):
        alert = self.get_object()
        classification = classify_and_store(alert, request.user)
        return Response(AlertClassificationSerializer(classification).data)

    @action(detail=True, methods=["post"])
    def enrich(self, request, pk=None):
        alert = self.get_object()
        classification, findings = enrich_alert(alert, request.user)
        return Response(
            {
                "classification": AlertClassificationSerializer(classification).data,
                "findings": findings,
            }
        )

    @action(detail=True, methods=["post"], url_path="process-async")
    def process_async(self, request, pk=None):
        alert = self.get_object()
        user_id = request.user.id if request.user.is_authenticated else None
        try:
            task = process_alert_task.delay(alert.id, user_id)
        except Exception as exc:
            return Response(
                {
                    "status": "BROKER_UNAVAILABLE",
                    "detail": str(exc),
                    "hint": "Start Redis/Celery or use the synchronous classify and enrich endpoints.",
                },
                status=503,
            )
        return Response(
            {"status": "QUEUED", "task_id": task.id, "alert_id": alert.id},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=True, methods=["post"], url_path="create-incident")
    def create_incident(self, request, pk=None):
        alert = self.get_object()
        incident = create_incident_from_alert(alert, request.user)
        from incidents.serializers import SecurityIncidentSerializer

        return Response(SecurityIncidentSerializer(incident).data, status=status.HTTP_201_CREATED)


class AlertClassificationViewSet(OrganizationScopedViewSet):
    queryset = AlertClassification.objects.select_related("alert", "alert__organization").all()
    serializer_class = AlertClassificationSerializer
    permission_classes = [CanManageSOC]
    organization_field = "alert__organization"

    def get_queryset(self):
        queryset = super().get_queryset()
        alert_id = self.request.query_params.get("alert")
        if alert_id:
            queryset = queryset.filter(alert_id=alert_id)
        return queryset
