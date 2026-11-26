from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from config.ui import can_manage, organization_for_request
from detections.backtesting import backtest_all, backtest_rule
from detections.models import DetectionHit, DetectionRule
from detections.services import (
    create_alert_from_hit,
    escalate_hit,
    evaluate_all,
    evaluate_rule,
    review_hit,
)


@login_required
def detections_view(request):
    organization = organization_for_request(request)
    if not organization:
        return render(
            request,
            "detections/list.html",
            {"rules": [], "hits": [], "error": "No organization assigned."},
        )
    rules = DetectionRule.objects.filter(organization=organization).order_by("rule_id")
    hits = (
        DetectionHit.objects.filter(organization=organization)
        .select_related("rule", "alert", "incident", "indicator")
        .order_by("-detected_at")[:200]
    )
    if request.method == "POST" and can_manage(request):
        action = request.POST.get("action")
        if action == "evaluate-all":
            result = evaluate_all(organization, request.user)
            messages.success(
                request,
                f"Evaluated {result['evaluated']} rules; {result['new_hits']} new hits.",
            )
        elif action == "evaluate":
            rule = get_object_or_404(
                DetectionRule, id=request.POST.get("rule_id"), organization=organization
            )
            created = evaluate_rule(rule, request.user)
            messages.success(request, f"{rule.name} produced {created} new hit(s).")
        elif action == "backtest":
            rule = get_object_or_404(
                DetectionRule, id=request.POST.get("rule_id"), organization=organization
            )
            result = backtest_rule(rule)
            messages.success(
                request,
                f"Backtest: {result['matched']} match(es) from {result['evaluated']} record(s); "
                f"{result['recommendation']}",
            )
        elif action == "backtest-all":
            result = backtest_all(organization)
            messages.success(
                request,
                f"Backtested {result['rules_evaluated']} rule(s); "
                f"{result['total_matches']} total match(es).",
            )
        else:
            hit = get_object_or_404(
                DetectionHit, id=request.POST.get("hit_id"), organization=organization
            )
            if action == "review":
                review_hit(
                    hit, request.POST.get("status"), request.user, request.POST.get("note", "")
                )
                messages.success(request, "Detection hit reviewed.")
            elif action == "to-alert":
                create_alert_from_hit(hit, request.user)
                messages.success(request, "Detection hit converted to a security alert.")
            elif action == "escalate":
                escalate_hit(hit, request.user, note=request.POST.get("note", ""))
                messages.success(request, "Detection hit escalated to an incident.")
        return redirect("detections:detections")
    return render(
        request,
        "detections/list.html",
        {
            "rules": rules,
            "hits": hits,
            "statuses": DetectionHit.Status.choices,
            "can_manage_view": can_manage(request),
            "error": "",
        },
    )
