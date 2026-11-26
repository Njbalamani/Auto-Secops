from django.conf import settings
from django.db import models


class AutomationWorkflow(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="workflows"
    )
    name = models.CharField(max_length=180)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    conditions = models.JSONField(default=dict, blank=True)
    actions = models.JSONField(default=list, blank=True)
    requires_approval = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_workflows",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "name"], name="uniq_workflow_org_name")
        ]

    def __str__(self):
        return self.name


class WorkflowExecution(models.Model):
    class Status(models.TextChoices):
        PENDING_APPROVAL = "PENDING_APPROVAL", "Pending Approval"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="workflow_executions"
    )
    workflow = models.ForeignKey(
        AutomationWorkflow, on_delete=models.CASCADE, related_name="executions"
    )
    alert = models.ForeignKey(
        "alerts.SecurityAlert", on_delete=models.SET_NULL, null=True, blank=True
    )
    incident = models.ForeignKey(
        "incidents.SecurityIncident", on_delete=models.SET_NULL, null=True, blank=True
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.RUNNING)
    context = models.JSONField(default=dict, blank=True)
    results = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True)
    triggered_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-triggered_at"]
        indexes = [models.Index(fields=["organization", "status"])]

    def __str__(self):
        return f"{self.workflow.name} - {self.status}"


class ApprovalRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="approval_requests"
    )
    execution = models.ForeignKey(
        WorkflowExecution, on_delete=models.CASCADE, related_name="approvals"
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="requested_approvals",
    )
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="decided_approvals",
    )
    requested_action = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    decision_note = models.TextField(blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-requested_at"]
        indexes = [models.Index(fields=["organization", "status"])]

    def __str__(self):
        return f"Approval for {self.execution.workflow.name}"
