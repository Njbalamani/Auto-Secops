from rest_framework import serializers

from assets.models import Asset, AssetRiskAssessment, Vulnerability


class AssetSerializer(serializers.ModelSerializer):
    latest_risk_score = serializers.SerializerMethodField()
    latest_risk_level = serializers.SerializerMethodField()
    open_vulnerabilities = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = "__all__"
        read_only_fields = ["created_at", "updated_at"]

    def get_latest_risk_score(self, obj):
        assessment = obj.risk_assessments.order_by("-assessed_at").first()
        return assessment.risk_score if assessment else None

    def get_latest_risk_level(self, obj):
        assessment = obj.risk_assessments.order_by("-assessed_at").first()
        return assessment.risk_level if assessment else None

    def get_open_vulnerabilities(self, obj):
        return obj.vulnerabilities.exclude(
            status__in=[Vulnerability.Status.REMEDIATED, Vulnerability.Status.RISK_ACCEPTED]
        ).count()


class VulnerabilitySerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.hostname", read_only=True)

    class Meta:
        model = Vulnerability
        fields = "__all__"
        read_only_fields = ["discovered_at"]


class AssetRiskAssessmentSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.hostname", read_only=True)

    class Meta:
        model = AssetRiskAssessment
        fields = "__all__"
        read_only_fields = ["assessed_at"]
