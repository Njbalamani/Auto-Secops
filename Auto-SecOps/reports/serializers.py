from rest_framework import serializers

from reports.models import Report


class ReportSerializer(serializers.ModelSerializer):
    pdf_url = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = "__all__"
        read_only_fields = ["created_at", "pdf"]

    def get_pdf_url(self, obj):
        return obj.pdf.url if obj.pdf else ""
