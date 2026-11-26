from django.utils import timezone

from audit.services import log_action
from automation.models import ApprovalRequest, WorkflowExecution
from incidents.models import IncidentTimeline, InvestigationNote
from incidents.services import _classification

SENSITIVE_ACTIONS = {
    "block_ip",
    "disable_account",
    "isolate_host",
    "delete_data",
    "revoke_sessions",
}


def _action_parts(action):
    if isinstance(action, dict):
        return str(action.get("type", "")).strip().lower(), action.get("params", {}) or {}
    return str(action).strip().lower(), {}


def workflow_matches(workflow, alert, incident=None):
    if not workflow.enabled:
        return False
    conditions = workflow.conditions or {}
    classification = _classification(alert)
    severities = conditions.get("severities") or []
    categories = conditions.get("categories") or []
    min_risk = int(conditions.get("min_risk_score") or 0)
    source_kinds = conditions.get("source_kinds") or []
    require_incident = bool(conditions.get("require_incident"))
    require_malicious = bool(conditions.get("require_malicious_indicator"))

    if severities and alert.severity not in severities:
        return False
    if categories and classification.category not in categories:
        return False
    if classification.risk_score < min_risk:
        return False
    if source_kinds and (not alert.source or alert.source.kind not in source_kinds):
        return False
    if require_incident and not incident:
        return False
    if require_malicious:
        evidence = classification.evidence or {}
        findings = evidence.get("enrichment", [])
        if not any(item.get("malicious") for item in findings):
            return False
    return True


def _record_safe_action(execution, action_name, params, incident, actor):
    summary = f"Automation action recorded: {action_name}."
    if action_name == "add_note" and incident:
        note = str(params.get("note") or f"Workflow {execution.workflow.name} executed.")
        InvestigationNote.objects.create(incident=incident, author=actor, note=note)
        summary = "Workflow added an investigation note."
    if incident:
        IncidentTimeline.objects.create(
            incident=incident,
            event_type="AUTOMATION_ACTION",
            actor=actor,
            summary=summary,
            metadata={
                "workflow_id": execution.workflow.id,
                "execution_id": execution.id,
                "action": action_name,
                "params": params,
                "infrastructure_changed": False,
            },
        )
    return {
        "action": action_name,
        "status": "RECORDED",
        "detail": summary,
        "infrastructure_changed": False,
    }


def execute_for_alert(alert, actor=None, incident=None):
    executions = []
    workflows = alert.organization.workflows.filter(enabled=True).prefetch_related("organization")
    for workflow in workflows:
        if not workflow_matches(workflow, alert, incident):
            continue
        execution = WorkflowExecution.objects.create(
            organization=alert.organization,
            workflow=workflow,
            alert=alert,
            incident=incident,
            status=WorkflowExecution.Status.RUNNING,
            context={
                "alert_id": alert.id,
                "incident_id": incident.id if incident else None,
                "matched_at": timezone.now().isoformat(),
            },
            results=[],
        )
        results = []
        requested_approval = False
        for action in workflow.actions or []:
            action_name, params = _action_parts(action)
            if not action_name:
                continue
            if action_name in SENSITIVE_ACTIONS or workflow.requires_approval:
                ApprovalRequest.objects.create(
                    organization=alert.organization,
                    execution=execution,
                    requested_by=actor,
                    requested_action={"action": action_name, "params": params},
                    status=ApprovalRequest.Status.PENDING,
                )
                results.append(
                    {
                        "action": action_name,
                        "status": "PENDING_APPROVAL",
                        "detail": "No infrastructure change performed; approval required.",
                        "infrastructure_changed": False,
                    }
                )
                requested_approval = True
            else:
                results.append(_record_safe_action(execution, action_name, params, incident, actor))

        execution.results = results
        execution.status = (
            WorkflowExecution.Status.PENDING_APPROVAL
            if requested_approval
            else WorkflowExecution.Status.COMPLETED
        )
        if execution.status == WorkflowExecution.Status.COMPLETED:
            execution.completed_at = timezone.now()
        execution.save(update_fields=["status", "results", "completed_at"])
        log_action(
            alert.organization,
            actor,
            "workflow.executed",
            "WorkflowExecution",
            execution.id,
            {"workflow": workflow.name, "status": execution.status, "actions": len(results)},
        )
        executions.append(execution)
    return executions


def decide_approval(approval, actor, approved, note=""):
    if approval.status != ApprovalRequest.Status.PENDING:
        raise ValueError("Approval request has already been decided.")
    approval.approver = actor
    approval.decided_at = timezone.now()
    approval.decision_note = note
    approval.status = (
        ApprovalRequest.Status.APPROVED if approved else ApprovalRequest.Status.REJECTED
    )
    approval.save()
    execution = approval.execution
    results = list(execution.results or [])
    action_data = approval.requested_action or {}
    action_name = str(action_data.get("action", "requested_action"))
    if approved:
        results.append(
            {
                "action": action_name,
                "status": "APPROVED_RECORDED",
                "detail": "Approval recorded. External infrastructure change not performed by this demo engine.",
                "infrastructure_changed": False,
                "approved_by": actor.username if actor else "",
            }
        )
        execution.status = WorkflowExecution.Status.COMPLETED
    else:
        results.append(
            {
                "action": action_name,
                "status": "REJECTED",
                "detail": note or "Approval rejected; no action performed.",
                "infrastructure_changed": False,
            }
        )
        execution.status = WorkflowExecution.Status.CANCELLED
    execution.results = results
    execution.completed_at = timezone.now()
    execution.save(update_fields=["results", "status", "completed_at"])
    log_action(
        approval.organization,
        actor,
        "approval.decided",
        "ApprovalRequest",
        approval.id,
        {"decision": approval.status, "execution_id": execution.id},
    )
    return approval
