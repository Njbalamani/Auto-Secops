import html
import os
from collections import Counter

from django.conf import settings
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from alerts.models import AlertClassification, SecurityAlert
from audit.services import log_action
from incidents.models import SecurityIncident
from intelligence.models import ThreatIntelligenceRecord
from reports.models import Report


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    return styles


def _table(rows, widths=None):
    table = Table(rows, colWidths=widths, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9ca3af")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ]
        )
    )
    return table


def _safe(value):
    return html.escape(str(value if value not in (None, "") else "-"))


def _incident_story(incident, styles):
    story = [
        Paragraph(f"Incident Report: {_safe(incident.title)}", styles["Title"]),
        Paragraph(
            f"Generated {timezone.now().isoformat()} | Priority {incident.priority} | "
            f"Severity {incident.severity} | Status {incident.status}",
            styles["Normal"],
        ),
        Spacer(1, 10),
        Paragraph("Summary", styles["Heading2"]),
        Paragraph(_safe(incident.description), styles["BodyText"]),
        Spacer(1, 8),
    ]
    metadata = [
        ["Field", "Value"],
        ["Incident ID", str(incident.id)],
        ["Risk score", str(incident.risk_score)],
        ["Created", incident.created_at.isoformat()],
        ["MITRE techniques", ", ".join(incident.mitre_techniques or []) or "-"],
    ]
    story.append(_table(metadata, [140, 380]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Classification Evidence", styles["Heading2"]))
    classification = getattr(incident.alert, "classification", None) if incident.alert else None
    if classification:
        evidence_rows = [
            ["Attribute", "Value"],
            ["Category", classification.category],
            ["Confidence", f"{classification.confidence:.1%}"],
            ["Method", classification.method],
            ["Model", classification.model_version],
            ["Explanation", classification.explanation.get("summary", "")],
        ]
        story.append(_table(evidence_rows, [140, 380]))
        enrichment = (classification.evidence or {}).get("enrichment", [])
        if enrichment:
            story.append(Spacer(1, 8))
            story.append(Paragraph("Threat Intelligence Matches", styles["Heading2"]))
            rows = [["Indicator", "Type", "Malicious", "Sources"]]
            for item in enrichment[:20]:
                rows.append(
                    [
                        item.get("value", ""),
                        item.get("indicator_type", ""),
                        "Yes" if item.get("malicious") else "No",
                        ", ".join(
                            record.get("source_name", "") for record in item.get("records", [])
                        )[:180],
                    ]
                )
            story.append(_table(rows, [140, 70, 70, 240]))
    else:
        story.append(Paragraph("No AI classification evidence is available.", styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Investigation Timeline", styles["Heading2"]))
    timeline_rows = [["When", "Event", "Summary"]]
    for event in incident.timeline.all()[:30]:
        timeline_rows.append([event.occurred_at.isoformat(), event.event_type, event.summary[:240]])
    story.append(_table(timeline_rows, [120, 110, 290]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommended Actions", styles["Heading2"]))
    for recommendation in incident.recommendations or []:
        story.append(Paragraph(f"• {_safe(recommendation)}", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            _safe(settings.AI_MODEL_DISCLAIMER),
            styles["Small"],
        )
    )
    return story


def _executive_story(organization, styles):
    alert_count = SecurityAlert.objects.filter(organization=organization).count()
    incident_count = SecurityIncident.objects.filter(organization=organization).count()
    open_count = SecurityIncident.objects.filter(
        organization=organization,
        status__in=[SecurityIncident.Status.NEW, SecurityIncident.Status.IN_PROGRESS],
    ).count()
    critical_count = SecurityIncident.objects.filter(
        organization=organization, severity=SecurityIncident.Severity.CRITICAL
    ).count()
    categories = Counter(
        AlertClassification.objects.filter(alert__organization=organization).values_list(
            "category", flat=True
        )
    )
    story = [
        Paragraph(f"Executive Security Summary: {_safe(organization.name)}", styles["Title"]),
        Paragraph(f"Generated {timezone.now().isoformat()}", styles["Normal"]),
        Spacer(1, 10),
        _table(
            [
                ["Metric", "Value"],
                ["Alerts processed", str(alert_count)],
                ["Incidents", str(incident_count)],
                ["Open incidents", str(open_count)],
                ["Critical incidents", str(critical_count)],
            ],
            [220, 120],
        ),
        Spacer(1, 10),
        Paragraph("Category Distribution", styles["Heading2"]),
        _table([["Category", "Count"]] + [[key, str(value)] for key, value in categories.items()]),
    ]
    return story


def _threat_intel_story(organization, styles):
    records = ThreatIntelligenceRecord.objects.filter(organization=organization).select_related(
        "indicator"
    )[:100]
    rows = [["Indicator", "Type", "Source", "Malicious", "Confidence"]]
    for record in records:
        rows.append(
            [
                record.indicator.value,
                record.indicator.indicator_type,
                record.source_name,
                "Yes" if record.malicious else "No",
                str(record.confidence),
            ]
        )
    return [
        Paragraph(f"Threat Intelligence Summary: {_safe(organization.name)}", styles["Title"]),
        Paragraph(f"Generated {timezone.now().isoformat()}", styles["Normal"]),
        Spacer(1, 10),
        _table(rows, [170, 70, 130, 70, 80]),
    ]


def generate_report(organization, report_type, actor=None, incident=None, title=""):
    if report_type == Report.ReportType.INCIDENT and not incident:
        raise ValueError("Incident reports require an incident.")
    if report_type == Report.ReportType.INCIDENT:
        default_title = f"Incident Report - {incident.title}"
    elif report_type == Report.ReportType.EXECUTIVE:
        default_title = f"Executive Summary - {organization.name}"
    else:
        default_title = f"Threat Intelligence - {organization.name}"
    report = Report.objects.create(
        organization=organization,
        title=title or default_title[:220],
        report_type=report_type,
        incident=incident,
        generated_by=actor,
        metadata={"generated_at": timezone.now().isoformat()},
    )
    styles = _styles()
    if report_type == Report.ReportType.INCIDENT:
        story = _incident_story(incident, styles)
    elif report_type == Report.ReportType.EXECUTIVE:
        story = _executive_story(organization, styles)
    else:
        story = _threat_intel_story(organization, styles)

    reports_dir = os.path.join(settings.MEDIA_ROOT, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    relative_name = f"reports/report_{report.id}.pdf"
    absolute_path = os.path.join(settings.MEDIA_ROOT, relative_name)
    SimpleDocTemplate(
        absolute_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=report.title,
    ).build(story)
    report.pdf.name = relative_name
    report.save(update_fields=["pdf"])
    log_action(
        organization,
        actor,
        "report.generated",
        "Report",
        report.id,
        {"report_type": report_type},
    )
    return report
