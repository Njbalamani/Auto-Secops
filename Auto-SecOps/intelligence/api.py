import json

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from alerts.api import request_organization
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet
from intelligence.enrichment import import_stix_bundle, import_taxii_feed
from intelligence.models import ThreatIndicator, ThreatIntelligenceRecord
from intelligence.serializers import ThreatIndicatorSerializer, ThreatIntelligenceSerializer


class ThreatIndicatorViewSet(OrganizationScopedViewSet):
    queryset = ThreatIndicator.objects.select_related("organization").all()
    serializer_class = ThreatIndicatorSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        value = self.request.query_params.get("value")
        if value:
            queryset = queryset.filter(value__icontains=value)
        return queryset


class ThreatIntelligenceViewSet(OrganizationScopedViewSet):
    queryset = ThreatIntelligenceRecord.objects.select_related("organization", "indicator").all()
    serializer_class = ThreatIntelligenceSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.query_params.get("malicious") in {"1", "true", "yes"}:
            queryset = queryset.filter(malicious=True)
        return queryset

    @action(detail=False, methods=["post"], url_path="import-stix")
    def import_stix(self, request):
        organization = request_organization(request)
        uploaded = request.FILES.get("file")
        try:
            if uploaded:
                bundle = json.load(uploaded)
            else:
                bundle = request.data.get("bundle")
                if isinstance(bundle, str):
                    bundle = json.loads(bundle)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Invalid STIX bundle: {exc}") from exc
        if not isinstance(bundle, dict):
            raise ValidationError("Provide a STIX bundle object or file.")
        created = import_stix_bundle(organization, bundle, request.user)
        return Response({"created": created}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"])
    def taxii(self, request):
        organization = request_organization(request)
        return Response(import_taxii_feed(organization, request.user))
