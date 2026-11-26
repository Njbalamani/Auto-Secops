from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from config.exports import csv_response
from config.permissions import CanManageSOC
from config.viewsets import OrganizationScopedViewSet
from detections.backtesting import backtest_all, backtest_rule
from detections.models import DetectionHit, DetectionRule
from detections.serializers import DetectionHitSerializer, DetectionRuleSerializer
from detections.services import (
    create_alert_from_hit,
    escalate_hit,
    evaluate_all,
    evaluate_rule,
    review_hit,
)


class DetectionRuleViewSet(OrganizationScopedViewSet):
    queryset = DetectionRule.objects.select_related("organization", "created_by").all()
    serializer_class = DetectionRuleSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        rule_type = self.request.query_params.get("rule_type")
        if rule_type:
            queryset = queryset.filter(rule_type=rule_type)
        if self.request.query_params.get("enabled") in {"1", "true", "yes"}:
            queryset = queryset.filter(enabled=True)
        return queryset

    @action(detail=True, methods=["post"])
    def evaluate(self, request, pk=None):
        rule = self.get_object()
        lookback_hours = int(request.data.get("lookback_hours", 24))
        created = evaluate_rule(rule, request.user, lookback_hours)
        return Response({"rule_id": rule.rule_id, "new_hits": created})

    @action(detail=False, methods=["post"], url_path="evaluate-all")
    def evaluate_all(self, request):
        user = request.user
        if user.is_platform_admin and request.data.get("organization"):
            from django.shortcuts import get_object_or_404

            from organizations.models import Organization

            organization = get_object_or_404(Organization, id=request.data["organization"])
        elif user.organization:
            organization = user.organization
        else:
            raise ValidationError("Assign an organization or provide an organization identifier.")
        return Response(
            evaluate_all(organization, user, int(request.data.get("lookback_hours", 24)))
        )

    @action(detail=True, methods=["post"], url_path="backtest")
    def backtest(self, request, pk=None):
        rule = self.get_object()
        return Response(
            backtest_rule(
                rule,
                request.data.get("lookback_hours", 168),
                request.data.get("limit", 1000),
            )
        )

    @action(detail=False, methods=["post"], url_path="backtest-all")
    def backtest_all(self, request):
        user = request.user
        if user.is_platform_admin and request.data.get("organization"):
            from django.shortcuts import get_object_or_404

            from organizations.models import Organization

            organization = get_object_or_404(Organization, id=request.data["organization"])
        elif user.organization:
            organization = user.organization
        else:
            raise ValidationError("Assign an organization or provide an organization identifier.")
        return Response(
            backtest_all(
                organization,
                request.data.get("lookback_hours", 168),
                request.data.get("limit", 500),
            )
        )

    @action(detail=True, methods=["post"])
    def toggle(self, request, pk=None):
        rule = self.get_object()
        rule.enabled = not rule.enabled
        rule.save(update_fields=["enabled", "updated_at"])
        return Response(DetectionRuleSerializer(rule).data)

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "rule_id",
            "name",
            "rule_type",
            "severity",
            "enabled",
            "last_evaluated_at",
            "conditions",
        ]
        rows = [
            [
                rule.rule_id,
                rule.name,
                rule.rule_type,
                rule.severity,
                rule.enabled,
                rule.last_evaluated_at.isoformat() if rule.last_evaluated_at else "",
                rule.conditions,
            ]
            for rule in self.get_queryset()[:10000]
        ]
        return csv_response("autosecops-detection-rules.csv", headers, rows)


class DetectionHitViewSet(OrganizationScopedViewSet):
    queryset = DetectionHit.objects.select_related(
        "organization", "rule", "alert", "incident", "indicator", "reviewer"
    ).all()
    serializer_class = DetectionHitSerializer
    permission_classes = [CanManageSOC]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        if params.get("status"):
            queryset = queryset.filter(status=params["status"])
        if params.get("severity"):
            queryset = queryset.filter(severity=params["severity"])
        if params.get("rule"):
            queryset = queryset.filter(rule_id=params["rule"])
        return queryset

    @action(detail=True, methods=["post"])
    def review(self, request, pk=None):
        hit = self.get_object()
        status_value = request.data.get("status")
        if not status_value:
            raise ValidationError("status is required.")
        try:
            review_hit(hit, status_value, request.user, request.data.get("note", ""))
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        return Response(DetectionHitSerializer(hit).data)

    @action(detail=True, methods=["post"], url_path="to-alert")
    def to_alert(self, request, pk=None):
        hit = self.get_object()
        alert = create_alert_from_hit(hit, request.user)
        from alerts.serializers import SecurityAlertSerializer

        return Response(SecurityAlertSerializer(alert).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def escalate(self, request, pk=None):
        hit = self.get_object()
        incident = escalate_hit(
            hit,
            request.user,
            run_workflows=str(request.data.get("run_workflows", "false")).lower()
            in {"1", "true", "yes"},
            note=request.data.get("note", ""),
        )
        from incidents.serializers import SecurityIncidentSerializer

        return Response(SecurityIncidentSerializer(incident).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"], url_path="export-csv")
    def export_csv(self, request):
        headers = [
            "id",
            "detected_at",
            "rule_id",
            "title",
            "severity",
            "status",
            "alert_id",
            "incident_id",
            "evidence",
        ]
        rows = [
            [
                hit.id,
                hit.detected_at.isoformat(),
                hit.rule.rule_id,
                hit.title,
                hit.severity,
                hit.status,
                hit.alert_id or "",
                hit.incident_id or "",
                hit.evidence,
            ]
            for hit in self.get_queryset()[:10000]
        ]
        return csv_response("autosecops-detection-hits.csv", headers, rows)
