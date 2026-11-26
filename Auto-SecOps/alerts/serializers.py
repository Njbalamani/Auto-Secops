from rest_framework import serializers

from alerts.models import AlertClassification, AlertSource, SecurityAlert


class AlertSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertSource
        fields = "__all__"


class AlertClassificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertClassification
        fields = "__all__"
        read_only_fields = ["classified_at"]


class SecurityAlertSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    category = serializers.CharField(source="classification.category", read_only=True)
    risk_score = serializers.IntegerField(source="classification.risk_score", read_only=True)

    class Meta:
        model = SecurityAlert
        fields = [
            "id",
            "source",
            "source_name",
            "external_id",
            "title",
            "description",
            "alert_type",
            "severity",
            "status",
            "source_ip",
            "destination_ip",
            "user_identity",
            "event_at",
            "received_at",
            "raw_payload",
            "normalized",
            "category",
            "risk_score",
        ]
        read_only_fields = ["received_at", "normalized", "category", "risk_score"]
