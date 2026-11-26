from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from automation.engine import decide_approval
from automation.models import ApprovalRequest, AutomationWorkflow, WorkflowExecution
from automation.serializers import (
    ApprovalRequestSerializer,
    AutomationWorkflowSerializer,
    WorkflowExecutionSerializer,
)
from config.permissions import CanApprove, CanManageSOC
from config.viewsets import OrganizationScopedViewSet


class AutomationWorkflowViewSet(OrganizationScopedViewSet):
    queryset = AutomationWorkflow.objects.select_related("organization").all()
    serializer_class = AutomationWorkflowSerializer
    permission_classes = [CanManageSOC]

    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        workflow = self.get_object()
        alert_id = request.data.get("alert")
        if not alert_id:
            raise ValidationError("alert is required.")
        from alerts.models import SecurityAlert

        alert = SecurityAlert.objects.filter(
            id=alert_id, organization_id=workflow.organization_id
        ).first()
        if not alert:
            raise ValidationError("Alert not found in workflow organization.")
        if not workflow.enabled:
            raise ValidationError("Workflow is disabled.")
        from automation.engine import workflow_matches

        if not workflow_matches(workflow, alert):
            raise ValidationError("Alert does not match workflow conditions.")
        from automation.models import WorkflowExecution

        execution = WorkflowExecution.objects.create(
            organization=workflow.organization,
            workflow=workflow,
            alert=alert,
            status=WorkflowExecution.Status.RUNNING,
            context={"alert_id": alert.id, "manual": True},
        )
        from automation.engine import SENSITIVE_ACTIONS, _action_parts, _record_safe_action

        results = []
        needs_approval = False
        for action_item in workflow.actions or []:
            action_name, params = _action_parts(action_item)
            if not action_name:
                continue
            if action_name in SENSITIVE_ACTIONS or workflow.requires_approval:
                ApprovalRequest.objects.create(
                    organization=workflow.organization,
                    execution=execution,
                    requested_by=request.user,
                    requested_action={"action": action_name, "params": params},
                )
                needs_approval = True
                results.append(
                    {
                        "action": action_name,
                        "status": "PENDING_APPROVAL",
                        "infrastructure_changed": False,
                    }
                )
            else:
                results.append(
                    _record_safe_action(execution, action_name, params, None, request.user)
                )
        execution.results = results
        execution.status = (
            WorkflowExecution.Status.PENDING_APPROVAL
            if needs_approval
            else WorkflowExecution.Status.COMPLETED
        )
        execution.save(update_fields=["status", "results"])
        return Response(WorkflowExecutionSerializer(execution).data, status=201)


class WorkflowExecutionViewSet(OrganizationScopedViewSet):
    queryset = WorkflowExecution.objects.select_related(
        "organization", "workflow", "alert", "incident"
    ).all()
    serializer_class = WorkflowExecutionSerializer
    permission_classes = [CanManageSOC]


class ApprovalRequestViewSet(OrganizationScopedViewSet):
    queryset = ApprovalRequest.objects.select_related(
        "organization", "execution", "requested_by", "approver"
    ).all()
    serializer_class = ApprovalRequestSerializer

    def get_permissions(self):
        if self.action in {"decide"}:
            return [CanApprove()]
        return [CanManageSOC()]

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.query_params.get("status"):
            queryset = queryset.filter(status=self.request.query_params["status"])
        return queryset

    @action(detail=True, methods=["post"])
    def decide(self, request, pk=None):
        approval = self.get_object()
        approved = request.data.get("approved")
        if not isinstance(approved, bool):
            raise ValidationError("approved must be a boolean.")
        decide_approval(approval, request.user, approved, request.data.get("note", ""))
        return Response(ApprovalRequestSerializer(approval).data)
