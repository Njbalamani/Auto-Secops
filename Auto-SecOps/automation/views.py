from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from automation.engine import decide_approval, execute_for_alert
from automation.models import ApprovalRequest, AutomationWorkflow, WorkflowExecution
from config.ui import can_approve, can_manage, organization_for_request


@login_required
def workflow_list(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request,
            "automation/list.html",
            {
                "workflows": [],
                "executions": [],
                "approvals": [],
                "error": "No organization assigned.",
            },
        )
    workflows = AutomationWorkflow.objects.filter(organization=organization).order_by("name")
    executions = (
        WorkflowExecution.objects.filter(organization=organization)
        .select_related("workflow", "alert")
        .order_by("-triggered_at")[:100]
    )
    approvals = (
        ApprovalRequest.objects.filter(organization=organization)
        .select_related("execution__workflow", "requested_by", "approver")
        .order_by("-requested_at")[:100]
    )
    if request.method == "POST":
        if request.POST.get("action") == "decide" and can_approve(request):
            approval = get_object_or_404(
                ApprovalRequest,
                id=request.POST.get("approval_id"),
                organization=organization,
            )
            decide_approval(
                approval,
                request.user,
                request.POST.get("decision") == "approve",
                request.POST.get("note", ""),
            )
            messages.success(request, f"Approval {approval.status.lower()} recorded.")
        elif request.POST.get("action") == "run" and can_manage(request):
            from alerts.models import SecurityAlert

            get_object_or_404(
                AutomationWorkflow, id=request.POST.get("workflow_id"), organization=organization
            )
            alert = SecurityAlert.objects.filter(
                id=request.POST.get("alert_id"), organization=organization
            ).first()
            if not alert:
                messages.error(request, "Alert not found in organization.")
            else:
                executions_new = len(execute_for_alert(alert, request.user))
                messages.success(request, f"Executed {executions_new} matching workflow(s).")
        return redirect("automation:workflows")
    return render(
        request,
        "automation/list.html",
        {
            "workflows": workflows,
            "executions": executions,
            "approvals": approvals,
            "error": "",
        },
    )
