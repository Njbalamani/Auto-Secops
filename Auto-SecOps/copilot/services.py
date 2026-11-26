from collections import Counter
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

from alerts.models import SecurityAlert
from assets.models import Vulnerability
from automation.models import ApprovalRequest
from detections.models import DetectionHit
from incidents.models import SecurityIncident
from riskfabric.services import attack_surface_summary, build_attack_paths, forecast_risk


def _iso_now():
    return datetime.now(dt_timezone.utc).isoformat()


def build_briefing(organization, actor=None):
    now = timezone.now()
    paths = build_attack_paths(organization, limit=5)
    summary = attack_surface_summary(organization)
    forecast = forecast_risk(organization)
    open_incidents = SecurityIncident.objects.filter(organization=organization).exclude(
        status__in=[SecurityIncident.Status.RESOLVED, SecurityIncident.Status.CLOSED]
    )
    new_hits = DetectionHit.objects.filter(
        organization=organization, status=DetectionHit.Status.NEW
    )
    pending_approvals = ApprovalRequest.objects.filter(
        organization=organization, status=ApprovalRequest.Status.PENDING
    )
    recent_alerts = SecurityAlert.objects.filter(
        organization=organization, received_at__gte=now - timedelta(hours=24)
    )
    severities = Counter(recent_alerts.values_list("severity", flat=True))

    actions = []
    for path in paths[:3]:
        actions.append(
            {
                "priority": "P1" if path["severity"] == "CRITICAL" else "P2",
                "title": f"Remediate {path['vulnerability']['cve']} on {path['asset']['hostname']}",
                "rationale": (
                    f"Risk score {path['score']} with {len(path['evidence']['hit_ids'])} correlated detection hit(s) "
                    f"and {len(path['evidence']['incident_ids'])} incident(s)."
                ),
                "recommended_action": path["recommendation"],
                "requires_human_approval": True,
                "evidence": {
                    "attack_path": path["id"],
                    "asset": path["asset"]["hostname"],
                    "vulnerability": path["vulnerability"]["cve"],
                },
            }
        )
    if new_hits.exists():
        actions.append(
            {
                "priority": "P2",
                "title": f"Review {new_hits.count()} untriaged detection hit(s)",
                "rationale": "Unreviewed detections can hide active correlation patterns.",
                "recommended_action": "Triage newest hits and promote confirmed activity to an incident.",
                "requires_human_approval": True,
                "evidence": {"hit_ids": list(new_hits.values_list("id", flat=True)[:10])},
            }
        )
    if pending_approvals.exists():
        actions.append(
            {
                "priority": "P2",
                "title": f"Decide {pending_approvals.count()} pending automation approval(s)",
                "rationale": "Queued approvals block response workflows until reviewed.",
                "recommended_action": "Approve only verified, policy-compliant actions; reject the rest.",
                "requires_human_approval": True,
                "evidence": {
                    "approval_ids": list(pending_approvals.values_list("id", flat=True)[:10])
                },
            }
        )

    headline = (
        f"{summary['attack_paths']} active attack path(s); risk trend is {forecast['trend']} "
        f"with a projected score of {forecast['projected_score']}."
    )
    shift_summary = [
        f"{recent_alerts.count()} alert(s) in the last 24 hours "
        f"({severities.get('HIGH', 0)} high, {severities.get('CRITICAL', 0)} critical).",
        f"{open_incidents.count()} open incident(s) and {new_hits.count()} untriaged detection hit(s).",
        f"{summary['exploitable_vulnerabilities']} exploitable vulnerability(ies) across "
        f"{summary['internet_exposed_assets']} internet-exposed asset(s).",
    ]
    watchlist = [
        {
            "type": "indicator",
            "value": indicator,
            "reason": "Correlated with a scored attack path.",
        }
        for path in paths
        for indicator in path["evidence"]["indicator_values"][:2]
    ][:8]
    if not watchlist and paths:
        watchlist = [
            {
                "type": "asset",
                "value": paths[0]["asset"]["hostname"],
                "reason": "Highest scoring exposure in the live risk fabric.",
            }
        ]

    return {
        "service": "AutoSecOps Analyst Copilot",
        "mode": "DETERMINISTIC_DECISION_SUPPORT",
        "generated_at": _iso_now(),
        "organization": organization.slug,
        "actor": actor.username if actor else None,
        "headline": headline,
        "shift_summary": shift_summary,
        "priority_actions": actions,
        "watchlist": watchlist,
        "forecast": forecast,
        "data_sources": [
            "alerts",
            "detection_hits",
            "incidents",
            "approvals",
            "assets",
            "vulnerabilities",
            "threat_indicators",
        ],
        "confidence": forecast["confidence"],
        "disclaimer": settings.AI_MODEL_DISCLAIMER,
    }


def answer_question(organization, question, actor=None):
    text = (question or "").strip().lower()
    if not text:
        return {
            "question": question or "",
            "intent": "INVALID",
            "answer": "Ask a question about incidents, detections, exposure, risk, or recommendations.",
            "evidence": [],
            "generated_at": _iso_now(),
        }

    if any(word in text for word in ["incident", "case"]):
        incidents = SecurityIncident.objects.filter(organization=organization).exclude(
            status__in=[SecurityIncident.Status.RESOLVED, SecurityIncident.Status.CLOSED]
        )
        titles = list(incidents.values_list("title", flat=True)[:5])
        answer = f"There are {incidents.count()} open incident(s). " + (
            "Top items: " + "; ".join(titles) + "." if titles else "No open incidents."
        )
        intent = "INCIDENT_STATUS"
        evidence = [{"type": "incident", "value": title} for title in titles]
    elif any(word in text for word in ["detection", "hit", "rule"]):
        hits = DetectionHit.objects.filter(organization=organization).select_related("rule")
        new_hits = hits.filter(status=DetectionHit.Status.NEW).count()
        rules = list(hits.values_list("rule__rule_id", flat=True)[:5])
        answer = f"There are {new_hits} new detection hit(s). Recent rules: {', '.join(rules) or 'none'}."
        intent = "DETECTION_STATUS"
        evidence = [{"type": "rule", "value": rule} for rule in rules]
    elif any(word in text for word in ["vulnerab", "asset", "exposure", "patch", "cve"]):
        paths = build_attack_paths(organization, limit=3)
        exploitable = Vulnerability.objects.filter(
            organization=organization, exploit_available=True
        ).count()
        answer = f"There are {exploitable} exploitable vulnerability(ies). " + (
            "Top exposure: "
            + paths[0]["asset"]["hostname"]
            + " via "
            + paths[0]["vulnerability"]["cve"]
            + "."
            if paths
            else "No active attack paths were scored."
        )
        intent = "EXPOSURE_STATUS"
        evidence = [
            {"type": "attack_path", "value": path["id"], "score": path["score"]} for path in paths
        ]
    elif any(word in text for word in ["recommend", "should", "priorit", "next"]):
        briefing = build_briefing(organization, actor)
        answer = (
            " ".join(
                action["title"] + ": " + action["recommended_action"]
                for action in briefing["priority_actions"][:3]
            )
            or "No immediate priority actions were identified."
        )
        intent = "RECOMMENDATIONS"
        evidence = briefing["priority_actions"][:3]
    else:
        briefing = build_briefing(organization, actor)
        answer = briefing["headline"] + " " + " ".join(briefing["shift_summary"])
        intent = "BRIEFING"
        evidence = [{"type": "forecast", "value": briefing["forecast"]}]

    return {
        "question": question,
        "intent": intent,
        "answer": answer,
        "evidence": evidence,
        "actor": actor.username if actor else None,
        "generated_at": _iso_now(),
        "disclaimer": settings.AI_MODEL_DISCLAIMER,
    }
