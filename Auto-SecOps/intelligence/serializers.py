from rest_framework import serializers

from intelligence.models import ThreatIndicator, ThreatIntelligenceRecord


class ThreatIndicatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatIndicator
        fields = "__all__"
        read_only_fields = ["first_seen", "last_seen"]


class ThreatIntelligenceSerializer(serializers.ModelSerializer):
    indicator_value = serializers.CharField(source="indicator.value", read_only=True)
    indicator_type = serializers.CharField(source="indicator.indicator_type", read_only=True)

    class Meta:
        model = ThreatIntelligenceRecord
        fields = "__all__"
        read_only_fields = ["created_at"]
