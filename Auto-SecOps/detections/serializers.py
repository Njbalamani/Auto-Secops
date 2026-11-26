from rest_framework import serializers

from detections.models import DetectionHit, DetectionRule


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = "__all__"
        read_only_fields = ["created_at", "updated_at", "last_evaluated_at"]


class DetectionHitSerializer(serializers.ModelSerializer):
    rule_name = serializers.CharField(source="rule.name", read_only=True)
    rule_id = serializers.CharField(source="rule.rule_id", read_only=True)

    class Meta:
        model = DetectionHit
        fields = "__all__"
        read_only_fields = ["detected_at", "reviewed_at"]
