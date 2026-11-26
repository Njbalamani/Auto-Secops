from django.utils import timezone

from alerts.models import SecurityAlert
from audit.services import log_action
from incidents.models import (
    IncidentAssignment,
    IncidentTimeline,
    InvestigationNote,
    SecurityIncident,
)

RECOMMENDATIONS = {
    "SUSPICIOUS_LOGIN": [
        "Force password reset for affected identity after verification.",
        "Review authentication logs for the source IP and nearby time window.",
        "Enable or tighten MFA on the affected account.",
    ],
    "MALWARE": [
        "Isolate affected endpoint after analyst approval.",
        "Collect the sample and inspect process lineage with EDR.",
        "Search the fleet for matching hashes and beacon domains.",
    ],
    "NETWORK_INTRUSION": [
        "Review firewall and IDS logs for the full source session.",
        "Check exposed services for known vulnerabilities.",
        "Block the source only after approved change authorization.",
    ],
    "PHISHING": [
        "Quarantine similar messages across the mail gateway.",
        "Reset credentials for users who interacted with the message.",
        "Run a targeted awareness follow-up for recipients.",
    ],
    "PRIVILEGE_ESCALATION": [
        "Review recent privileged group changes and approving tickets.",
        "Rotate credentials for impacted privileged accounts.",
        "Validate IAM policies for excessive permissions.",
    ],
    "OTHER": [
        "Validate the source event and correlate with nearby telemetry.",
        "Confirm whether the event is expected behavior.",
        "Document closure rationale if classified as benign.",
    ],
}


def _severity_and_priority(risk_score):
    if risk_score >= 75:
        return SecurityIncident.Severity.CRITICAL, SecurityIncident.Priority.P1
    if risk_score >= 55:
        return SecurityIncident.Severity.HIGH, SecurityIncident.Priority.P2
    if risk_score >= 30:
        return SecurityIncident.Severity.MEDIUM, SecurityIncident.Priority.P3
    return SecurityIncident.Severity.LOW, SecurityIncident.Priority.P4


def _classification(alert):
    classification = getattr(alert, "classification", None)
    if not classification:
        from mlengine.services import classify_and_store

        classification = classify_and_store(alert)
    return classification


def create_incident_from_alert(alert, actor=None):
    classification = _classification(alert)
    severity, priority = _severity_and_priority(classification.risk_score)
    evidence = classification.evidence or {}
    category_label = classification.category.replace("_", " ").title()
    incident = SecurityIncident.objects.create(
        organization=alert.organization,
        title=f"{category_label}: {alert.title}"[:240],
        description=(
            f"Source: {alert.source.name if alert.source else 'unknown'}\n"
            f"Severity: {alert.severity}\n"
            f"Event: {alert.event_at.isoformat()}\n"
            f"Details: {alert.description or 'No additional description supplied.'}"
        ),
        alert=alert,
        severity=severity,
        priority=priority,
        status=SecurityIncident.Status.NEW,
        risk_score=classification.risk_score,
        created_by=actor,
        mitre_techniques=evidence.get("mitre_techniques", []),
        recommendations=RECOMMENDATIONS.get(classification.category, RECOMMENDATIONS["OTHER"]),
    )
    alert.status = SecurityAlert.Status.INCIDENT
    alert.save(update_fields=["status"])
    IncidentTimeline.objects.create(
        incident=incident,
        event_type="INCIDENT_CREATED",
        actor=actor,
        summary=f"Incident created from alert {alert.external_id or alert.id}.",
        metadata={
            "alert_id": alert.id,
            "category": classification.category,
            "risk_score": classification.risk_score,
        },
    )
    log_action(
        alert.organization,
        actor,
        "incident.created",
        "SecurityIncident",
        incident.id,
        {"alert_id": alert.id, "severity": severity, "priority": priority},
    )
    return incident


def assign_incident(incident, user, actor=None):
    IncidentAssignment.objects.filter(incident=incident, active=True).update(
        active=False, unassigned_at=timezone.now()
    )
    assignment = IncidentAssignment.objects.create(
        incident=incident, user=user, assigned_by=actor, active=True
    )
    IncidentTimeline.objects.create(
        incident=incident,
        event_type="ASSIGNED",
        actor=actor,
        summary=f"Incident assigned to {user.display_name or user.username}.",
        metadata={"user_id": user.id},
    )
    log_action(
        incident.organization,
        actor,
        "incident.assigned",
        "SecurityIncident",
        incident.id,
        {"assigned_to": user.username},
    )
    return assignment


def add_investigation_note(incident, author, note):
    record = InvestigationNote.objects.create(incident=incident, author=author, note=note)
    IncidentTimeline.objects.create(
        incident=incident,
        event_type="NOTE_ADDED",
        actor=author,
        summary="Investigation note added.",
        metadata={"note_id": record.id},
    )
    log_action(
        incident.organization,
        author,
        "incident.note_added",
        "SecurityIncident",
        incident.id,
        {"note_id": record.id},
    )
    return record


def change_status(incident, status, actor=None, note=""):
    previous = incident.status
    incident.status = status
    if status == SecurityIncident.Status.IN_PROGRESS and not incident.acknowledged_at:
        incident.acknowledged_at = timezone.now()
    if status == SecurityIncident.Status.RESOLVED and not incident.resolved_at:
        incident.resolved_at = timezone.now()
    if status == SecurityIncident.Status.CLOSED:
        if not incident.resolved_at:
            incident.resolved_at = timezone.now()
        incident.closed_at = timezone.now()
    incident.save()
    IncidentTimeline.objects.create(
        incident=incident,
        event_type="STATUS_CHANGED",
        actor=actor,
        summary=f"Status changed from {previous} to {status}. {note}".strip(),
        metadata={"previous": previous, "current": status},
    )
    log_action(
        incident.organization,
        actor,
        "incident.status_changed",
        "SecurityIncident",
        incident.id,
        {"previous": previous, "current": status},
    )
    return incident
