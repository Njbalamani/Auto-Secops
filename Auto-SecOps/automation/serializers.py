from rest_framework import serializers

from automation.models import ApprovalRequest, AutomationWorkflow, WorkflowExecution


class AutomationWorkflowSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomationWorkflow
        fields = "__all__"
        read_only_fields = ["created_at"]


class WorkflowExecutionSerializer(serializers.ModelSerializer):
    workflow_name = serializers.CharField(source="workflow.name", read_only=True)

    class Meta:
        model = WorkflowExecution
        fields = "__all__"
        read_only_fields = ["triggered_at", "completed_at"]


class ApprovalRequestSerializer(serializers.ModelSerializer):
    workflow_name = serializers.CharField(source="execution.workflow.name", read_only=True)

    class Meta:
        model = ApprovalRequest
        fields = "__all__"
        read_only_fields = ["requested_at", "decided_at"]
