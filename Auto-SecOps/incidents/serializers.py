from rest_framework import serializers

from incidents.models import IncidentAssignment, InvestigationNote, SecurityIncident


class SecurityIncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityIncident
        fields = "__all__"
        read_only_fields = ["created_at", "acknowledged_at", "resolved_at", "closed_at"]


class InvestigationNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvestigationNote
        fields = "__all__"
        read_only_fields = ["created_at", "updated_at"]


class IncidentAssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = IncidentAssignment
        fields = "__all__"
        read_only_fields = ["assigned_at", "unassigned_at"]
